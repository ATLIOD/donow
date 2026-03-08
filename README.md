# do now

[![Go Report Card](https://goreportcard.com/badge/github.com/ATLIOD/donow?t=1)](https://goreportcard.com/report/github.com/ATLIOD/donow)


do now is currently in the process of being deployed at a new url

do now is a task management web app built with **Go**, **HTMX**, **AlpineJS** and **PostgreSQL**, designed to help you manage your tasks efficiently through a clean and simple interface. This app focuses on providing a seamless user experience with dynamic interactions.

## Features

- **Task Management**: Create, update, and mark tasks as completed.
 ![image](https://github.com/user-attachments/assets/7acfbf23-a46d-4750-b4ab-d3b6c8359456)

- **Pomodoro Timer**: Built-in Pomodoro timer to help boost productivity.
  ![image](https://github.com/user-attachments/assets/f4102f39-866a-49a4-95f1-450de4dd40c0)

- **User Account Creation**: Users can create accounts to save their data across different machines and browsers.
- **User Sessions**: Makes use of sessions for that users do not require an account to keep their changes on one machine between sessions.
- **Email management**: Makes use of email servers and APIs to send users password reset emails.

## Technologies Used

- **Go**: The backend is written in Go (Golang), providing a fast and lightweight HTTP server.
- **HTMX**: A modern framework for building dynamic user interfaces with minimal JavaScript.
- **Redis**: Used for in memory storage of information that requires a set TTL such as user sessions and One-Time-Passwords.
- **AlpineJS**: A lightweight JavaScript framework used for enhancing front-end interactivity in the timer.
- **PostgreSQL**: Used for persistent data storage, including user and task information.
- **Docker**: The app is packaged with Docker, making it easy to deploy server-side.
- **Caddy**: The deployment server makes use of caddy to handle reverse proxying, TLS certificates, and HTTPS.

## Accessing the Website

Since this is a web app, you don't need to install anything on your local machine to use it. Once deployed, you can simply visit the URL at [donow.it.com](https://www.donow.it.com)

## License

This project is currently under the terms of the GNU GENERAL PUBLIC LICENSE V3.0
