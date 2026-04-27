"""Vector store using ChromaDB for semantic search over findings."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import chromadb
from chromadb.config import Settings
from loguru import logger
from pydantic import BaseModel

from fenrir.config import AppConfig


class VectorResult(BaseModel):
    """Result from vector search."""
    id: str
    content: str
    metadata: dict[str, Any]
    distance: float


class VectorStore:
    """ChromaDB-backed vector store for finding similarity search."""

    def __init__(self, config: AppConfig):
        self.config = config
        self._client: chromadb.ClientAPI | None = None
        self._findings_collection: chromadb.Collection | None = None
        self._techniques_collection: chromadb.Collection | None = None
        self._chains_collection: chromadb.Collection | None = None

    @property
    def _chroma_client(self) -> chromadb.ClientAPI:
        if self._client is None:
            self.config.brain.chroma_db_dir.mkdir(parents=True, exist_ok=True)
            self._client = chromadb.PersistentClient(
                path=str(self.config.brain.chroma_db_dir),
                settings=Settings(anonymized_telemetry=False),
            )
        return self._client

    @property
    def findings_collection(self) -> chromadb.Collection:
        if self._findings_collection is None:
            self._findings_collection = self._chroma_client.get_or_create_collection(
                name="findings",
                metadata={"hnsw:space": "cosine"},
            )
        return self._findings_collection

    @property
    def techniques_collection(self) -> chromadb.Collection:
        if self._techniques_collection is None:
            self._techniques_collection = self._chroma_client.get_or_create_collection(
                name="techniques",
                metadata={"hnsw:space": "cosine"},
            )
        return self._techniques_collection

    @property
    def chains_collection(self) -> chromadb.Collection:
        if self._chains_collection is None:
            self._chains_collection = self._chroma_client.get_or_create_collection(
                name="chains",
                metadata={"hnsw:space": "cosine"},
            )
        return self._chains_collection

    def _get_collection(self, collection_type: str) -> chromadb.Collection:
        """Get collection by type name."""
        if collection_type == "findings":
            return self.findings_collection
        elif collection_type == "techniques":
            return self.techniques_collection
        elif collection_type == "chains":
            return self.chains_collection
        else:
            return self.findings_collection

    def add_text(
        self,
        text: str,
        collection: str = "findings",
        metadata: dict[str, str] | None = None,
        doc_id: str | None = None,
    ) -> str:
        """Add text to vector store."""
        if doc_id is None:
            doc_id = f"doc_{self._get_collection(collection).count()}"

        col = self._get_collection(collection)
        embeds = self._generate_embedding(text)

        col.add(
            documents=[text],
            embeddings=[embeds],
            metadatas=[metadata or {"source": "fenrir"}],
            ids=[doc_id],
        )
        logger.debug(f"Added to vector store: {doc_id} ({len(text)} chars)")
        return doc_id

    def add_finding(
        self,
        finding_type: str,
        content: str,
        target: str,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Add a finding with structured metadata."""
        doc_id = f"finding_{target}_{finding_type}_{self.findings_collection.count()}"
        meta = metadata or {}
        meta.update({"finding_type": finding_type, "target": target})
        return self.add_text(content, "findings", meta, doc_id)

    def add_technique(
        self,
        name: str,
        description: str,
        metadata: dict[str, str] | None = None,
    ) -> str:
        """Add a technique to the technique library."""
        doc_id = f"tech_{name.replace(' ', '_').lower()}"
        meta = metadata or {}
        meta.update({"name": name})
        return self.add_text(description, "techniques", meta, doc_id)

    def search(
        self,
        query: str,
        collection: str = "findings",
        n_results: int = 5,
        where: dict[str, str] | None = None,
    ) -> list[VectorResult]:
        """Semantic search over findings."""
        col = self._get_collection(collection)
        embeds = self._generate_embedding(query)

        kwargs: dict[str, Any] = {
            "query_embeddings": [embeds],
            "n_results": n_results,
            "include": ["documents", "metadatas", "distances"],
        }

        if where:
            kwargs["where"] = where

        results = col.query(**kwargs)

        vector_results = []
        if results["ids"] and results["ids"][0]:
            for i, doc_id in enumerate(results["ids"][0]):
                vector_results.append(
                    VectorResult(
                        id=doc_id,
                        content=results["documents"][0][i] if results["documents"] else "",
                        metadata=results["metadatas"][0][i] if results["metadatas"] else {},
                        distance=results["distances"][0][i] if results["distances"] else 0.0,
                    )
                )

        return vector_results

    def search_by_target(
        self, query: str, target: str, n_results: int = 5
    ) -> list[VectorResult]:
        """Search findings for a specific target."""
        return self.search(
            query, "findings", n_results, where={"target": target}
        )

    def _generate_embedding(self, text: str) -> list[float]:
        """Generate embedding using either OpenAI API or a simple fallback.

        For production, use OpenAI embeddings. For development without API key,
        use a simple character-level frequency embedding as fallback.
        """
        # Try OpenAI-compatible embedding API
        try:
            return self._openai_embedding(text)
        except Exception as e:
            logger.warning(f"OpenAI embedding failed ({e}), using fallback")
            return self._fallback_embedding(text)

    def _openai_embedding(self, text: str) -> list[float]:
        """Generate embedding via OpenAI-compatible API."""
        import httpx

        api_key = self.config.llm_providers.embedding_api_key
        base_url = self.config.llm_providers.embedding_base_url.rstrip("/")
        model = self.config.llm_providers.embedding_model

        if not api_key:
            raise ValueError("No embedding API key configured")

        response = httpx.post(
            f"{base_url}/embeddings",
            headers={"Authorization": f"Bearer {api_key}"},
            json={"model": model, "input": text},
            timeout=30.0,
        )
        response.raise_for_status()
        data = response.json()
        return data["data"][0]["embedding"]

    @staticmethod
    def _fallback_embedding(text: str, dim: int = 384) -> list[float]:
        """Simple fallback embedding using character n-gram frequencies."""
        import hashlib

        result = []
        n = 3  # trigrams
        text_lower = text.lower()

        for i in range(dim):
            chunk = text_lower[i * n : (i + 1) * n + 2]
            if len(chunk) >= n:
                # Simple hash-based feature
                h = int(hashlib.md5(chunk.encode()).hexdigest(), 16)
                result.append((h % 1000) / 1000.0)
            else:
                result.append(0.0)

        # Normalize
        norm = sum(x * x for x in result) ** 0.5
        if norm > 0:
            result = [x / norm for x in result]
        return result

    def count(self, collection: str = "findings") -> int:
        """Count documents in a collection."""
        return self._get_collection(collection).count()

    def delete(self, doc_id: str, collection: str = "findings") -> None:
        """Delete a document by ID."""
        self._get_collection(collection).delete(ids=[doc_id])

    def clear(self, collection: str | None = None) -> None:
        """Clear a specific collection or all collections."""
        if collection:
            try:
                self._chroma_client.delete_collection(collection)
            except Exception:
                pass
        else:
            for name in ["findings", "techniques", "chains"]:
                try:
                    self._chroma_client.delete_collection(name)
                except Exception:
                    pass
