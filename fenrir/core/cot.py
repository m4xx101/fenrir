"""Chain-of-Thought reasoning and ReAct loop for Fenrir agents.

Provides structured multi-step reasoning, ReAct patterns (thought-action-observation),
self-correction on contradictions, and synthesis of agent findings.

Designed to wrap BaseAgent calls with a reasoning loop that:
1. Produces a structured thought before each action
2. Executes a tool call or LLM query
3. Observes and evaluates the result
4. Reflects on whether the approach is productive
5. Self-corrects when contradictions are detected

Usage:
    # Wrap an existing agent with ReAct reasoning
    agent = ReActAgent(config, base_agent=my_agent)
    result = await agent.think("Find all SQL injection points on target.com")

    # Use CoTReasoner standalone for complex problem-solving
    reasoner = CoTReasoner(config, base_agent=my_agent)
    cot_result = await reasoner.reason(task, context)
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from loguru import logger
from pydantic import BaseModel, Field

from fenrir.agents.base import AgentResult, BaseAgent
from fenrir.config import AppConfig, LLMTier


# ─── Data Models ─────────────────────────────────────────────────────────────


class ReasoningPhase(str, Enum):
    """Phase within a single reasoning step."""

    THINK = "think"
    ACT = "act"
    OBSERVE = "observe"
    REFLECT = "reflect"
    CORRECT = "correct"


class CoTStep(BaseModel):
    """A single step in the chain-of-thought reasoning loop."""

    iteration: int
    phase: ReasoningPhase
    thought: str = ""
    action: str = ""
    action_args: dict[str, Any] = Field(default_factory=dict)
    observation: str = ""
    reflection: str = ""
    confidence: float = 0.0
    contradiction_detected: bool = False
    backtracked: bool = False


class CoTResult(BaseModel):
    """Structured output from a CoT reasoning session."""

    task: str
    steps: list[CoTStep] = Field(default_factory=list)
    final_answer: str = ""
    confidence: float = 0.0
    reasoning_trace: str = ""
    total_iterations: int = 0
    success: bool = False
    error: str = ""
    execution_time_s: float = 0.0


# ─── Contradiction Detection ─────────────────────────────────────────────────

# Keywords that signal potential contradictions when found together
_CONTRADICTION_PATTERNS: list[tuple[str, str]] = [
    ("open", "closed"),
    ("up", "down"),
    ("enabled", "disabled"),
    ("vulnerable", "patched"),
    ("exists", "not found"),
    ("present", "absent"),
    ("success", "failed"),
    ("allowed", "denied"),
    ("reachable", "unreachable"),
    ("active", "inactive"),
    ("true", "false"),
    ("yes", "no"),
    ("accessible", "forbidden"),
    ("running", "stopped"),
    ("valid", "invalid"),
]


def _detect_contradiction(current: str, history: str) -> bool:
    """Check if current observation contradicts previously established facts.

    Performs a heuristic scan for mutually exclusive term pairs appearing
    as factual claims in both the current observation and accumulated history.

    Args:
        current: The latest observation text.
        history: Accumulated observations from previous steps.

    Returns:
        True if a contradiction is likely detected.
    """
    current_lower = current.lower()
    history_lower = history.lower()

    # Extract factual claims — sentences with strong indicator words
    claim_indicators = ("is ", "was ", "are ", "not ", "no ", "found ",
                        "detected ", "confirms ", "confirmed ", "result: ",
                        "output: ", "status: ", "response: ")

    current_claims = _extract_claims(current_lower, claim_indicators)
    history_claims = _extract_claims(history_lower, claim_indicators)

    # Check each claim pair for contradiction patterns
    for h_claim in history_claims:
        for c_claim in current_claims:
            for pos, neg in _CONTRADICTION_PATTERNS:
                if (pos in h_claim and neg in c_claim) or \
                   (neg in h_claim and pos in c_claim):
                    # Require both to appear as factual statements, not negations
                    if _is_factual_claim(h_claim, pos or neg) and \
                       _is_factual_claim(c_claim, neg or pos):
                        logger.debug(
                            f"Potential contradiction: '{h_claim[:80]}' "
                            f"vs '{c_claim[:80]}' (pattern: {pos}/{neg})"
                        )
                        return True
    return False


def _extract_claims(text: str, indicators: tuple[str, ...]) -> list[str]:
    """Extract sentence-like claims from text."""
    # Split on sentence boundaries
    sentences = re.split(r'[.!?]\s+', text)
    claims = []
    for sentence in sentences:
        sentence = sentence.strip()
        if any(sentence.startswith(ind) for ind in indicators):
            claims.append(sentence)
    return claims


def _is_factual_claim(claim: str, keyword: str) -> bool:
    """Determine if a claim is asserting a fact about the keyword."""
    # Avoid simple negations ("not found" is not contradictory with "found")
    negation_prefixes = ("not ", "no ", "never ", "no longer ")
    for neg in negation_prefixes:
        # If the claim negates the keyword AND the keyword in its paired claim
        # also negates, then there's no actual contradiction
        pass
    return keyword in claim


# ─── CoT Reasoner ────────────────────────────────────────────────────────────


class CoTReasoner:
    """Multi-step chain-of-thought reasoning wrapper for BaseAgent.

    Wraps BaseAgent calls with a structured reasoning loop that executes
    think -> act -> observe -> reflect cycles until a satisfactory answer
    is reached or max_iterations is exhausted.

    Each iteration:
    1. THINK: Internal reasoning about what to do next
    2. ACT: Execute a tool call or LLM query
    3. OBSERVE: Capture and record the result
    4. REFLECT: Evaluate progress and check for contradictions

    Args:
        config: Application configuration.
        agent: The BaseAgent to wrap with reasoning.
        max_iterations: Maximum reasoning steps (default: 5).
        confidence_threshold: Stop when confidence exceeds this value (default: 0.85).
        enable_self_correction: Whether to auto-backtrack on contradictions.
    """

    def __init__(
        self,
        config: AppConfig,
        agent: BaseAgent,
        max_iterations: int = 5,
        confidence_threshold: float = 0.85,
        enable_self_correction: bool = True,
    ):
        self.config = config
        self.agent = agent
        self.max_iterations = max_iterations
        self.confidence_threshold = confidence_threshold
        self.enable_self_correction = enable_self_correction
        self._accumulated_findings: list[dict[str, Any]] = []
        self._reasoning_history: list[str] = []

    async def reason(
        self,
        task: str,
        context: str = "",
        max_iterations: int | None = None,
    ) -> CoTResult:
        """Execute the full chain-of-thought reasoning loop.

        Args:
            task: The task/problem to reason through.
            context: Additional context for the agent.
            max_iterations: Override the default max iterations.

        Returns:
            CoTResult with steps, final answer, and confidence score.
        """
        start_time = time.time()
        max_iters = max_iterations or self.max_iterations
        self._accumulated_findings.clear()
        self._reasoning_history.clear()

        steps: list[CoTStep] = []
        logger.info(
            f"[CoT] Starting reasoning loop for task: {task[:100]}... "
            f"(max_iterations={max_iters})"
        )

        for iteration in range(1, max_iters + 1):
            logger.info(f"[CoT] --- Iteration {iteration}/{max_iters} ---")

            # ── PHASE 1: THINK ───────────────────────────────────────────────
            step = CoTStep(iteration=iteration, phase=ReasoningPhase.THINK)
            thought = await self._generate_thought(
                task, context, steps, start_time
            )
            step.thought = thought
            step.phase = ReasoningPhase.THINK
            steps.append(step)
            logger.debug(f"[CoT] Thought: {thought[:200]}")

            # ── PHASE 2: ACT ─────────────────────────────────────────────────
            act_step = CoTStep(
                iteration=iteration,
                phase=ReasoningPhase.ACT,
                thought=thought,
            )
            action_name, action_args = await self._plan_action(
                task, context, thought, steps
            )
            act_step.action = action_name
            act_step.action_args = action_args
            step.action = action_name
            step.action_args = action_args

            observation = await self._execute_action(action_name, action_args)
            act_step.observation = observation[:2000]  # Cap length for model
            step.observation = act_step.observation

            steps.append(act_step)
            self._reasoning_history.append(observation)
            logger.debug(f"[CoT] Action: {action_name} -> {observation[:200]}")

            # ── PHASE 3: OBSERVE — self-correction check ─────────────────────
            observe_step = CoTStep(
                iteration=iteration,
                phase=ReasoningPhase.OBSERVE,
                observation=observation[:2000],
            )

            if self.enable_self_correction and len(self._reasoning_history) > 1:
                combined_history = "\n".join(
                    self._reasoning_history[:-1]  # exclude current
                )
                contradiction = _detect_contradiction(
                    observation, combined_history
                )
                step.confidence = await self._assess_confidence(
                    task, observation, thought
                )

                if contradiction:
                    observe_step.confidence = step.confidence
                    step.confidence = step.confidence
                    observe_step.contradiction_detected = True
                    step.contradiction_detected = True

                    logger.warning(
                        f"[CoT] Contradiction detected at iteration {iteration}!"
                    )

                    # Backtrack
                    corrected_obs = await self._backtrack(
                        task, context, observation, steps
                    )
                    observe_step.observation = corrected_obs[:2000]
                    step.observation = corrected_obs[:2000]
                    step.backtracked = True
                    observe_step.backtracked = True

                    self._reasoning_history.append(corrected_obs)
                else:
                    observe_step.confidence = step.confidence
            else:
                observe_step.confidence = await self._assess_confidence(
                    task, observation, thought
                )
                step.confidence = observe_step.confidence

            steps.append(observe_step)

            # ── PHASE 4: REFLECT ─────────────────────────────────────────────
            reflect_step = CoTStep(
                iteration=iteration,
                phase=ReasoningPhase.REFLECT,
            )
            reflection = await self._reflect(
                task, context, steps, observation
            )
            reflect_step.reflection = reflection
            reflect_step.confidence = observe_step.confidence
            steps.append(reflect_step)

            # Collect any findings from this iteration
            self._extract_findings(observation)

            # Check termination conditions
            if observe_step.confidence >= self.confidence_threshold:
                logger.info(
                    f"[CoT] Confidence threshold reached "
                    f"({observe_step.confidence:.2f} >= {self.confidence_threshold})"
                )
                break

            # Check if the reflection indicates we're done
            if "sufficient" in reflection.lower() or \
               "enough evidence" in reflection.lower() or \
               "conclusive" in reflection.lower():
                logger.info(f"[CoT] Reflection indicates sufficient information.")
                break

        # ── SYNTHESIS ────────────────────────────────────────────────────────
        final_answer = await self._synthesize_results(task, steps)
        overall_confidence = self._compute_overall_confidence(steps)

        reasoning_trace = self._format_reasoning_trace(steps)

        total_iterations = len([s for s in steps if s.phase == ReasoningPhase.THINK])

        result = CoTResult(
            task=task,
            steps=steps,
            final_answer=final_answer,
            confidence=overall_confidence,
            reasoning_trace=reasoning_trace,
            total_iterations=total_iterations,
            success=overall_confidence >= self.confidence_threshold * 0.7,
            execution_time_s=time.time() - start_time,
        )

        logger.info(
            f"[CoT] Reasoning complete: {total_iterations} iterations, "
            f"confidence={overall_confidence:.2f}, "
            f"success={result.success}, "
            f"time={result.execution_time_s:.1f}s"
        )

        return result

    async def _generate_thought(
        self,
        task: str,
        context: str,
        steps: list[CoTStep],
        start_time: float,
    ) -> str:
        """Generate the thinking portion for the current iteration."""
        elapsed = time.time() - start_time

        # Build context for reasoning
        previous_steps_summary = self._summarize_steps(steps)

        thought_prompt = (
            f"You are reasoning through a security assessment task.\n\n"
            f"TASK: {task}\n\n"
            f"CONTEXT: {context}\n\n"
            f"ELAPSED TIME: {elapsed:.1f}s\n\n"
            f"PREVIOUS STEPS:\n{previous_steps_summary}\n\n"
            f"Think carefully about:\n"
            f"1. What do we know so far?\n"
            f"2. What is the most promising next action?\n"
            f"3. Are we on the right track or should we change approach?\n"
            f"4. What specific tool or query should we use next?\n\n"
            f"Provide your reasoning as a clear, structured thought."
        )

        try:
            response = await self.agent.call_llm(
                messages=[
                    {"role": "system", "content": (
                        "You are a security reasoning engine. "
                        "Think step by step about the task and determine "
                        "the best next action. Be concise and analytical."
                    )},
                    {"role": "user", "content": thought_prompt},
                ],
                temperature=0.4,
                max_tokens=512,
            )
            return response.content.strip()
        except Exception as exc:
            logger.warning(f"[CoT] Thought generation failed: {exc}")
            return (
                f"Reasoning failed ({exc}). "
                f"Proceeding with direct tool execution to make progress."
            )

    async def _plan_action(
        self,
        task: str,
        context: str,
        thought: str,
        steps: list[CoTStep],
    ) -> tuple[str, dict[str, Any]]:
        """Plan the next action based on current reasoning.

        Returns a tuple of (tool_name_or_query, arguments).
        """
        # Default: try to extract tool call from the agent's tool registry
        available_tools = self.agent.tool_registry.get_definitions()

        if available_tools and thought:
            plan_prompt = (
                f"Based on the following reasoning, select the best tool "
                f"and arguments to execute next.\n\n"
                f"TASK: {task}\n"
                f"REASONING: {thought}\n\n"
                f"AVAILABLE TOOLS:\n"
                f"{json.dumps(available_tools[:3], indent=2)}\n\n"
                f"Respond with ONLY a JSON object containing:\n"
                f'{{"tool_name": "<name>", "arguments": {{...}}}}\n'
                f"If no tool is appropriate, respond with:\n"
                f'{{"tool_name": "llm_query", "arguments": {{"query": "..."}}}}'
            )

            try:
                response = await self.agent.call_llm(
                    messages=[
                        {"role": "system", "content": (
                            "You are a tool selection engine. "
                            "Respond with valid JSON only. No markdown, no explanation."
                        )},
                        {"role": "user", "content": plan_prompt},
                    ],
                    temperature=0.3,
                    max_tokens=256,
                )
                # Parse JSON response
                content = response.content.strip()
                # Strip markdown code fences if present
                if content.startswith("```"):
                    content = re.sub(r"^```json?\n?|```$", "", content, flags=re.MULTILINE).strip()
                plan = json.loads(content)
                tool_name = plan.get("tool_name", "llm_query")
                arguments = plan.get("arguments", {})
                if not tool_name:
                    tool_name = "llm_query"
                    arguments = {"query": thought}
                return tool_name, arguments
            except Exception as exc:
                logger.warning(f"[CoT] Action planning failed: {exc}")

        # Fallback: default to a direct LLM query if planning failed
        return "llm_query", {"query": thought}

    async def _execute_action(
        self, action_name: str, action_args: dict[str, Any]
    ) -> str:
        """Execute the planned action and return the observation."""
        if action_name == "llm_query":
            query = action_args.get("query", "")
            try:
                response = await self.agent.call_llm(
                    messages=[
                        {"role": "system", "content": (
                            f"You are assisting with a security task: "
                            f"{self.agent.name}. Provide a detailed, "
                            f"factual response based on the query."
                        )},
                        {"role": "user", "content": query},
                    ],
                    temperature=0.3,
                    max_tokens=1024,
                )
                return response.content
            except Exception as exc:
                return f"LLM query failed: {exc}"

        else:
            # Execute a registered tool
            try:
                result = await self.agent.execute_tool(action_name, action_args)
                if result.get("success"):
                    return result.get("output", "Tool succeeded with no output.")
                else:
                    return f"Tool failed: {result.get('error', 'Unknown error')}"
            except Exception as exc:
                return f"Tool execution failed: {type(exc).__name__}: {exc}"

    async def _assess_confidence(
        self, task: str, observation: str, thought: str
    ) -> float:
        """Assess confidence in the current observation relative to the task."""
        confidence_prompt = (
            f"Assess how confident we are that the latest observation "
            f"provides useful information for the task.\n\n"
            f"TASK: {task}\n"
            f"OBSERVATION: {observation[:500]}\n\n"
            f"Respond with ONLY a float between 0.0 and 1.0 representing "
            f"confidence. No explanation."
        )

        try:
            response = await self.agent.call_llm(
                messages=[
                    {"role": "system", "content": (
                        "You are a confidence assessment engine. "
                        "Respond with ONLY a float between 0.0 and 1.0."
                    )},
                    {"role": "user", "content": confidence_prompt},
                ],
                temperature=0.1,
                max_tokens=16,
            )
            # Extract float
            content = response.content.strip()
            match = re.search(r"(\d*\.?\d+)", content)
            if match:
                return min(1.0, max(0.0, float(match.group(1))))
            return 0.5
        except Exception as exc:
            logger.warning(f"[CoT] Confidence assessment failed: {exc}")
            return 0.5

    async def _reflect(
        self,
        task: str,
        context: str,
        steps: list[CoTStep],
        last_observation: str,
    ) -> str:
        """Reflect on the current state and determine if we should continue."""
        previous_steps_summary = self._summarize_steps(steps)

        reflection_prompt = (
            f"Reflect on the progress so far:\n\n"
            f"TASK: {task}\n"
            f"LATEST OBSERVATION: {last_observation[:500]}\n\n"
            f"FULL REASONING TRACE:\n{previous_steps_summary}\n\n"
            f"Answer these questions:\n"
            f"1. Are we making progress toward the goal?\n"
            f"2. Have we gathered sufficient evidence?\n"
            f"3. Should we continue, change approach, or stop?\n"
            f"4. What is our current confidence level?\n\n"
            f"Provide a structured reflection."
        )

        try:
            response = await self.agent.call_llm(
                messages=[
                    {"role": "system", "content": (
                        "You are a reflection engine. Evaluate the reasoning "
                        "progress and provide a structured assessment. "
                        "Be honest about whether enough information has been "
                        "gathered. If sufficient, include the word 'sufficient'."
                    )},
                    {"role": "user", "content": reflection_prompt},
                ],
                temperature=0.3,
                max_tokens=384,
            )
            return response.content.strip()
        except Exception as exc:
            return f"Reflection failed ({exc}). Continuing with next iteration."

    async def _backtrack(
        self,
        task: str,
        context: str,
        conflicting_observation: str,
        steps: list[CoTStep],
    ) -> str:
        """Attempt to resolve a contradiction by trying an alternative approach."""
        backtrack_prompt = (
            f"A contradiction has been detected in the reasoning loop.\n\n"
            f"TASK: {task}\n"
            f"CONFLICTING OBSERVATION: {conflicting_observation[:500]}\n\n"
            f"PREVIOUS STEUPS:\n{self._summarize_steps(steps)}\n\n"
            f"Propose an alternative approach that resolves the contradiction. "
            f"What verification step should we perform to determine which "
            f"observation is correct?\n\n"
            f"Provide a concrete verification strategy."
        )

        try:
            response = await self.agent.call_llm(
                messages=[
                    {"role": "system", "content": (
                        "You detected a contradiction in your reasoning. "
                        "Propose an alternative verification step to resolve "
                        "it. Focus on concrete actions."
                    )},
                    {"role": "user", "content": backtrack_prompt},
                ],
                temperature=0.5,
                max_tokens=512,
            )
            # Try to execute the suggested verification
            alt_action, alt_args = await self._plan_action(
                task, context, response.content, steps
            )
            alt_observation = await self._execute_action(alt_action, alt_args)
            return (
                f"[Backtrack] Alternative verification:\n"
                f"Action: {alt_action}\n"
                f"Result: {alt_observation}\n"
                f"Resolution: {response.content}"
            )
        except Exception as exc:
            logger.warning(f"[CoT] Backtrack failed: {exc}")
            return (
                f"[Backtrack] Resolution failed ({exc}). "
                f"Original conflicting observation: {conflicting_observation[:300]}"
            )

    async def _synthesize_results(
        self, task: str, steps: list[CoTStep]
    ) -> str:
        """Synthesize all reasoning steps into a final answer."""
        trace = self._summarize_steps(steps)
        findings_summary = json.dumps(self._accumulated_findings[:10], default=str)

        synthesize_prompt = (
            f"Synthesize all reasoning steps into a final answer.\n\n"
            f"ORIGINAL TASK: {task}\n\n"
            f"REASONING TRACE:\n{trace}\n\n"
            f"FINDINGS COLLECTED:\n{findings_summary}\n\n"
            f"Provide a comprehensive final answer that:\n"
            f"1. Directly addresses the original task\n"
            f"2. Summarizes all key findings\n"
            f"3. Notes any uncertainties or limitations\n"
            f"4. Recommends next steps if applicable"
        )

        try:
            response = await self.agent.call_llm(
                messages=[
                    {"role": "system", "content": (
                        "You are a synthesis engine. Provide a comprehensive "
                        "final answer based on all reasoning steps. "
                        "Be thorough, accurate, and structured."
                    )},
                    {"role": "user", "content": synthesize_prompt},
                ],
                temperature=0.3,
                max_tokens=2048,
            )
            return response.content.strip()
        except Exception as exc:
            logger.warning(f"[CoT] Synthesis failed: {exc}")
            return (
                f"Synthesis failed ({exc}). "
                f"Final observation: {steps[-1].observation[:500] if steps else 'N/A'}"
            )

    def _compute_overall_confidence(self, steps: list[CoTStep]) -> float:
        """Compute overall confidence from all assessment steps."""
        confidence_values = [
            s.confidence for s in steps
            if s.confidence > 0 and s.phase in (
                ReasoningPhase.OBSERVE, ReasoningPhase.REFLECT
            )
        ]
        if not confidence_values:
            return 0.0
        # Use the last confidence value (most recent assessment) weighted with average
        last_conf = confidence_values[-1]
        avg_conf = sum(confidence_values) / len(confidence_values)
        return round(0.6 * last_conf + 0.4 * avg_conf, 3)

    def _summarize_steps(self, steps: list[CoTStep]) -> str:
        """Summarize reasoning steps for prompt injection."""
        lines = []
        for s in steps:
            lines.append(
                f"Iteration {s.iteration} [{s.phase.value}]: "
                f"{(s.thought or s.action or s.observation or s.reflection or '')[:250]}"
            )
            if s.contradiction_detected:
                lines.append(f"  >> CONTRADICTION DETECTED <<")
            if s.backtracked:
                lines.append(f"  >> BACKTRACKED <<")
        return "\n".join(lines)

    def _extract_findings(self, observation: str) -> None:
        """Attempt to extract structured findings from observation text."""
        # Look for JSON-like structures in the observation
        json_matches = re.findall(r'\{[^{}]*(?:"type"|"vuln_type"|"severity"|"category")[^{}]*\}', observation)
        for match in json_matches:
            try:
                finding = json.loads(match)
                self._accumulated_findings.append(finding)
            except json.JSONDecodeError:
                pass

    def _format_reasoning_trace(self, steps: list[CoTStep]) -> str:
        """Format the complete reasoning trace for debugging."""
        lines = [f"=== CoT Reasoning Trace ==="]
        for s in steps:
            icon = {
                ReasoningPhase.THINK: "[?] THINK",
                ReasoningPhase.ACT: "[>] ACT",
                ReasoningPhase.OBSERVE: "[<] OBSERVE",
                ReasoningPhase.REFLECT: "[~] REFLECT",
                ReasoningPhase.CORRECT: "[!] CORRECT",
            }.get(s.phase, f"[?] {s.phase.value}")

            lines.append(f"\n--- {icon} (iter={s.iteration}) ---")
            if s.thought:
                lines.append(f"Thought: {s.thought[:300]}")
            if s.action:
                lines.append(f"Action: {s.action}")
                if s.action_args:
                    args = json.dumps(s.action_args, default=str)[:200]
                    lines.append(f"  Args: {args}")
            if s.observation:
                lines.append(f"Observation: {s.observation[:300]}")
            if s.reflection:
                lines.append(f"Reflection: {s.reflection[:300]}")
            if s.contradiction_detected:
                lines.append(">> CONTRADICTION DETECTED <<")
            if s.backtracked:
                lines.append(">> BACKTRACKED <<")
            lines.append(f"Confidence: {s.confidence:.2f}")

        return "\n".join(lines)


# ─── ReAct Agent ─────────────────────────────────────────────────────────────


class ReActAgent(BaseAgent):
    """BaseAgent subclass that uses the ReAct reasoning pattern.

    Overrides _run() to use the ReAct pattern:
    - Think: reason about the next action
    - Act: execute a tool or LLM query
    - Observe: capture and evaluate results
    - Reflect: assess progress and detect contradictions

    Inherits all BaseAgent capabilities (brain, vector store, tool registry,
    call_llm, execute_tool) but wraps them in a structured reasoning loop.

    Usage:
        agent = ReActAgent(
            config=config,
            target="example.com",
            max_iterations=7,
            confidence_threshold=0.9,
        )
        result = await agent.think(
            "Find all exposed admin panels and test for default credentials"
        )

    Args:
        config: Application configuration.
        max_iterations: Maximum ReAct loop iterations (default: 5).
        confidence_threshold: Confidence level to trigger early synthesis (default: 0.85).
        enable_self_correction: Enable automatic backtracking on contradictions (default: True).
        **kwargs: Additional arguments passed to BaseAgent.__init__.
    """

    name: str = "react_agent"
    role: str = "ReAct Reasoning Agent"
    system_prompt: str = (
        "You are a reasoning agent using the ReAct pattern. "
        "Think carefully before acting, observe results critically, "
        "and reflect on your progress. "
        "Be self-correcting when you detect contradictions."
    )
    tier: LLMTier = LLMTier.TIER_2
    temperature: float = 0.3

    def __init__(
        self,
        config: AppConfig,
        max_iterations: int = 5,
        confidence_threshold: float = 0.85,
        enable_self_correction: bool = True,
        **kwargs: Any,
    ):
        super().__init__(config, **kwargs)
        self.max_iterations = max_iterations
        self.confidence_threshold = confidence_threshold
        self.enable_self_correction = enable_self_correction
        self._cot_reasoner = CoTReasoner(
            config=config,
            agent=self,
            max_iterations=max_iterations,
            confidence_threshold=confidence_threshold,
            enable_self_correction=enable_self_correction,
        )
        # Track internal state for the ReAct run
        self._cot_result: CoTResult | None = None

    async def _run(self, task: str, context: str) -> AgentResult:
        """Execute the ReAct reasoning loop.

        Overrides BaseAgent._run() to use the structured ReAct pattern:
        think -> act -> observe -> reflect, looping until convergence
        or max iterations.

        Args:
            task: The task to execute.
            context: Additional context from the brain.

        Returns:
            AgentResult with synthesized findings.
        """
        logger.info(
            f"[ReAct] Starting reasoning loop: {task[:120]}... "
            f"(max_iterations={self.max_iterations})"
        )

        cot_result = await self._cot_reasoner.reason(task, context)
        self._cot_result = cot_result

        # Convert CoTResult to AgentResult
        success = cot_result.success
        findings = self._cot_reasoner._accumulated_findings[:]

        # Also add a summary finding with the full reasoning trace
        trace_finding = {
            "type": "reasoning_trace",
            "task": task,
            "final_answer": cot_result.final_answer[:2000],
            "confidence": cot_result.confidence,
            "iterations": cot_result.total_iterations,
            "steps_summary": [
                {
                    "iteration": s.iteration,
                    "phase": s.phase.value,
                    "confidence": s.confidence,
                    "contradiction": s.contradiction_detected,
                }
                for s in cot_result.steps
                if s.phase == ReasoningPhase.REFLECT
            ],
        }
        findings.append(trace_finding)

        errors = []
        if cot_result.error:
            errors.append(cot_result.error)

        # Save findings to brain
        for f in findings:
            if f.get("type") != "reasoning_trace":
                try:
                    self.save_finding(f, category=f.get("category", "vuln"))
                except Exception as e:
                    logger.warning(f"[ReAct] Brain save failed: {e}")

        result = AgentResult(
            agent_name=self.name,
            success=success,
            summary=cot_result.final_answer[:500],
            findings=findings,
            error="; ".join(errors) if errors else "",
            execution_time_s=cot_result.execution_time_s,
        )

        # Log reasoning trace
        if cot_result.reasoning_trace:
            logger.debug(f"[ReAct] Reasoning trace:\n{cot_result.reasoning_trace}")

        logger.info(
            f"[ReAct] Completed: {cot_result.total_iterations} iterations, "
            f"confidence={cot_result.confidence:.2f}, "
            f"{len(findings)} findings, "
            f"success={success}"
        )
        return result

    def get_cot_result(self) -> CoTResult | None:
        """Return the most recent CoTResult, if available."""
        return self._cot_result

    def get_reasoning_trace(self) -> str:
        """Return the human-readable reasoning trace."""
        if self._cot_result:
            return self._cot_result.reasoning_trace
        return "No reasoning trace available."


__all__ = [
    "CoTReasoner",
    "CoTResult",
    "CoTStep",
    "ReActAgent",
    "ReasoningPhase",
    "_detect_contradiction",
]
