# Web Crawler Application

This web crawler application allows users to search websites, extract PDFs and analyze their content. It features user authentication, multi-level web crawling, PDF extraction, and visualization tools like word clouds.

## Features

- User authentication (register, login, password reset)
- Multi-level web crawling
- PDF detection and extraction
- Search history tracking
- Word frequency analysis
- Word cloud visualization
- User profile management

## Installation

### Running with Docker

1. Clone the repository or extract the project files
2. Open a command prompt in the project directory
3. Build and run the application using Docker (On Windows):
   ```
   docker-compose build
   ```
Then, run with: 
   ```
   docker-compose up
   ```

4. Access the application at http://localhost:5000

### Stopping the application

1. Press Ctrl+C in the command prompt
2. Run:
   ```
   docker-compose down
   ```

## Usage Guide

### Registration and Login

1. Register a new account with your email, nickname and password
2. Login with your credentials
3. Use the "Forgot Password" feature if needed

### Web Crawling

1. Navigate to the Search page
2. Enter a URL to crawl
3. Select the crawl depth level (1-3)
***Please note: After 'Start Crawling' Button is clicked, please wait for few minutes until the crawling process finishes.***
***Since it doesn't crawl duplicated urls, you may need check or clear the database to make sure the input url was not crawled before.***
5. View the results, including any PDFs found

### PDF Analysis

1. View your search history on the History page
2. Click on any PDF to view its details
3. Generate word clouds from selected PDFs
4. Search across all your extracted PDFs

### User Profile

1. Update your nickname or email
2. Change your password
3. View your account information

