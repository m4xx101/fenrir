package websocket

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// Message types for real-time broadcasts.
const (
	MsgTypeScanUpdate  = "scan_update"
	MsgTypeNewFinding  = "new_finding"
	MsgTypeAgentStatus = "agent_status"
	MsgTypeError       = "error"
	MsgTypePing        = "ping"
)

// WSMessage is the unified message format sent over WebSocket.
type WSMessage struct {
	Type      string    `json:"type"`
	Timestamp time.Time  `json:"timestamp"`
	Payload   any       `json:"payload"`
}

// Client represents a single WebSocket client connection.
type Client struct {
	hub  *Hub
	conn *websocket.Conn
	send chan []byte
	mu   sync.Mutex
}

// Hub maintains the set of active clients and broadcasts messages.
type Hub struct {
	clients    map[*Client]bool
	broadcast  chan []byte
	register   chan *Client
	unregister chan *Client
	mu         sync.RWMutex
}

// NewHub creates a new WebSocket hub.
func NewHub() *Hub {
	return &Hub{
		clients:    make(map[*Client]bool),
		broadcast:  make(chan []byte, 256),
		register:   make(chan *Client),
		unregister: make(chan *Client),
	}
}

// Run starts the hub's event loop. Call this in a goroutine.
func (h *Hub) Run() {
	for {
		select {
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
			log.Printf("websocket client connected. total=%d", len(h.clients))

		case client := <-h.unregister:
			h.mu.Lock()
			if h.clients[client] {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
			log.Printf("websocket client disconnected. total=%d", len(h.clients))

		case message := <-h.broadcast:
			h.mu.RLock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.RUnlock()
		}
	}
}

// ClientCount returns the number of active WebSocket clients.
func (h *Hub) ClientCount() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.clients)
}

// Broadcast sends a message to all connected clients.
func (h *Hub) Broadcast(msgType string, payload any) {
	msg := WSMessage{
		Type:      msgType,
		Timestamp: time.Now().UTC(),
		Payload:   payload,
	}
	data, err := json.Marshal(msg)
	if err != nil {
		log.Printf("websocket: failed to marshal broadcast: %v", err)
		return
	}
	h.broadcast <- data
}

// BroadcastScanUpdate sends a scan phase/status update to all clients.
func (h *Hub) BroadcastScanUpdate(scanID, phase, status, message string) {
	h.Broadcast(MsgTypeScanUpdate, map[string]string{
		"scan_id": scanID,
		"phase":   phase,
		"status":  status,
		"message": message,
	})
}

// BroadcastNewFinding sends a new finding to all clients.
func (h *Hub) BroadcastNewFinding(scanID, findingID, severity, findingType, description string) {
	h.Broadcast(MsgTypeNewFinding, map[string]string{
		"scan_id":     scanID,
		"finding_id":  findingID,
		"severity":    severity,
		"type":        findingType,
		"description": description,
	})
}

// BroadcastAgentStatus sends an agent status update to all clients.
func (h *Hub) BroadcastAgentStatus(agentID, status, action string) {
	h.Broadcast(MsgTypeAgentStatus, map[string]string{
		"agent_id": agentID,
		"status":   status,
		"action":   action,
	})
}

// HandleWebSocket upgrades an HTTP connection to WebSocket and registers the client.
func (h *Hub) HandleWebSocket(c *gin.Context) {
	upgrader := websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			return true // Can be restricted with config
		},
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
	}

	conn, err := upgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		log.Printf("websocket upgrade failed: %v", err)
		c.AbortWithError(http.StatusBadRequest, err)
		return
	}

	client := &Client{
		hub:  h,
		conn: conn,
		send: make(chan []byte, 256),
	}

	h.register <- client

	go client.writePump()
	go client.readPump()
}

// writePump pumps messages from the hub to the WebSocket connection.
func (c *Client) writePump() {
	ticker := time.NewTicker(30 * time.Second)
	defer func() {
		ticker.Stop()
		c.conn.Close()
	}()

	for {
		select {
		case message, ok := <-c.send:
			c.mu.Lock()
			if !ok {
				c.conn.WriteMessage(websocket.CloseMessage, []byte{})
				c.mu.Unlock()
				return
			}
			if err := c.conn.WriteMessage(websocket.TextMessage, message); err != nil {
				log.Printf("websocket write error: %v", err)
				c.mu.Unlock()
				return
			}
			c.mu.Unlock()

		case <-ticker.C:
			c.mu.Lock()
			if err := c.conn.WriteMessage(websocket.PingMessage, nil); err != nil {
				log.Printf("websocket ping error: %v", err)
				c.mu.Unlock()
				return
			}
			c.mu.Unlock()
		}
	}
}

// readPump pumps messages from the WebSocket connection to the hub.
func (c *Client) readPump() {
	defer func() {
		c.hub.unregister <- c
		c.conn.Close()
	}()

	for {
		_, message, err := c.conn.ReadMessage()
		if err != nil {
			if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
				log.Printf("websocket unexpected close: %v", err)
			}
			break
		}

		// Client can send ping messages
		var ping struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(message, &ping); err == nil && ping.Type == "ping" {
			c.mu.Lock()
			c.conn.WriteMessage(websocket.PongMessage, []byte("pong"))
			c.mu.Unlock()
		}
	}
}
