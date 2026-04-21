# 🛡️ Guardian SIEM & Active Defense System

An asymmetric, high-performance Security Information and Event Management (SIEM) MVP with built-in Intrusion Prevention System (IPS) capabilities. Built entirely with Golang and a robust microservices architecture.

![Architecture: Microservices](https://img.shields.io/badge/Architecture-Microservices-blue)
![Language: Go](https://img.shields.io/badge/Language-Go-00ADD8?logo=go)
![Container: Docker](https://img.shields.io/badge/Container-Docker-2496ED?logo=docker)
![Message Broker: RabbitMQ](https://img.shields.io/badge/Broker-RabbitMQ-FF6600?logo=rabbitmq)

## 📌 Project Overview
Guardian SIEM is designed to ingest, process, and react to security logs in real-time. Unlike passive monitoring tools, this system features an **Auto-Ban Mechanism** that physically blocks attackers at the API gateway when a threshold is breached, while providing deep forensics to a live, authoritative dashboard.

## 🏗️ Asymmetric Architecture
The system is divided into decoupled services communicating via message queues:

1. **Ingestion API (Go):** The front door. Receives logs, checks the Redis Blacklist, and forwards valid logs to RabbitMQ. Rejects blacklisted IPs with `403 Forbidden`.
2. **Message Broker (RabbitMQ):** Buffers incoming traffic, ensuring no data loss during high-volume DDoS or Brute-Force spikes.
3. **Defense Worker (Go):** Consumes logs, increments strike counters in Redis. Upon 5 failed attempts, it triggers the IPS:
   - Sets a 10-minute ban in Redis.
   - Saves forensics (`IP`, `User-Agent`, `HTTP Method`, `Count`) to PostgreSQL.
4. **Live Dashboard (HTML/JS/WebSocket):** An enterprise-grade, dark-mode radar screen that displays critical incidents in real-time without requiring page reloads.

## 🛠️ Tech Stack
- **Backend:** Golang (Fiber/Standard `net/http`)
- **Database (Forensics):** PostgreSQL
- **In-Memory Cache (Counters & Blacklist):** Redis
- **Message Queue:** RabbitMQ
- **Frontend UI:** HTML5, Vanilla JS, TailwindCSS, WebSockets
- **Infrastructure:** Docker & Docker Compose

## 🚀 Quick Start

### 1. Build and Run
Make sure you have Docker Desktop installed. Clone the repository and run:
```bash
docker-compose up -d --build
