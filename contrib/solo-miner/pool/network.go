package pool

import (
	"bufio"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"sync/atomic"
	"time"
)

const extranonce1Length = 4

var numberOfConnections atomic.Int64

type stratumClient struct {
	ip          string
	login       string
	extranonce1 string
	userAgent   string

	sessionID     string
	connection    net.Conn
	streamEncoder *json.Encoder
}

func (pool *PoolServer) listenForConnections() {
	pool.connectionTimeout = mustParseDuration(pool.config.ConnectionTimeout)

	addr, err := net.ResolveTCPAddr("tcp", ":"+pool.config.Port)
	if err != nil {
		panicOnError(err)
	}

	server, err := net.ListenTCP("tcp", addr)
	panicOnError(err)
	defer server.Close()

	for { // Listen for connections
		currentConns := numberOfConnections.Load()
		if currentConns > int64(pool.config.MaxConnections) {
			log.Printf("Maximum connections reached (%d/%d), rejecting new connections", currentConns, pool.config.MaxConnections)
			time.Sleep(100 * time.Millisecond)
			continue
		}

		con, err := server.AcceptTCP()
		if err != nil {
			log.Println(err)
			continue
		}
		con.SetKeepAlive(true)
		con.SetKeepAlivePeriod(30 * time.Second)

		ip, _, err := net.SplitHostPort(con.RemoteAddr().String())
		if err != nil {
			log.Println(err)
			con.Close()
			continue
		}

		log.Println("New Stratum Connection from: " + ip)

		if isBanned(ip) {
			con.Close()
			continue
		}

		client := &stratumClient{
			ip:          ip,
			extranonce1: uniqueExtranonce(extranonce1Length * 2),
			connection:  con,
		}

		numberOfConnections.Add(1)
		go pool.openNewConnection(client)
	}
}

const maxRequestSize = 1024

func (pool *PoolServer) openNewConnection(client *stratumClient) {
	defer func() {
		numberOfConnections.Add(-1)
		removeSession(client.sessionID)
		client.connection.Close()
	}()

	err := pool.handleStratumConnection(client)
	if err != nil {
		log.Println(err)
	}
}

func (pool *PoolServer) handleStratumConnection(client *stratumClient) error {
	client.streamEncoder = json.NewEncoder(client.connection)
	connectionBuffer := bufio.NewReaderSize(client.connection, maxRequestSize)

	// Set initial deadline
	client.connection.SetDeadline(time.Now().Add(pool.connectionTimeout))

	for {
		payload, isPrefix, err := connectionBuffer.ReadLine()
		if err == io.EOF {
			return errors.New("client disconnect: " + client.ip)
		}

		if isPrefix {
			log.Println("Socket flood detected from: " + client.ip)
			banClient(client)
			return err
		} else if err != nil {
			// Check if this is a TLS handshake attempt
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return errors.New("connection timeout: " + client.ip)
			}
			return errors.New("socket read error from: " + client.ip)
		}

		// Reset deadline after every successful read — FINDING-03 fix
		client.connection.SetDeadline(time.Now().Add(pool.connectionTimeout))

		if len(payload) > 1 {
			// Detect TLS handshake attempt (first byte 0x16 = TLS record type)
			if payload[0] == 0x16 || (len(payload) > 1 && payload[0] == 0x16 && payload[1] == 0x03) {
				log.Printf("TLS handshake detected from %s — use stratum+tcp:// not stratum+ssl://", client.ip)
				return errors.New("TLS handshake on plaintext port from: " + client.ip)
			}

			err = pool.respondToStratumClient(client, payload)
			if err != nil {
				return err
			}
		}
	}
}

func sendPacket(packet any, client *stratumClient) error {
	return client.streamEncoder.Encode(packet)
}

func mustParseDuration(s string) time.Duration {
	value, err := time.ParseDuration(s)
	if err != nil {
		panic("util: Can't parse duration `" + s + "`: " + err.Error())
	}
	return value
}
