# Nickel-Auth

Nickel-Auth is a proxy server designed to facilitate authentication between the iOS app [Nickel](https://github.com/tfourj/Nickel) and the [Cobalt.Tools](https://github.com/imputnet/cobalt) API servers because Swift lacks current turnstile implementation that cobalt uses to secure their servers.

## Features
- Acts as a bridge between the Nickel app and Cobalt.Tools API.
- Uses Apple's AppAttest authentication method to authenticate server with app.
- Enables the **Nickel-Auth** feature in the Nickel app for seamless authentication.
- Built-in rate limiting and security features
- Prometheus metrics for monitoring
- Auto-updating Docker containers with Watchtower

## Adding Your Instance to Nickel App
If you'd like to add your instance to the Nickel app, please contact us at [support@tfourj.com](mailto:support@tfourj.com).

You can also view a list of public instances at [Nickel's Website](https://getnickel.site/instances).

## Self-Hosting Tutorial

### Prerequisites
- [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) installed on your system.
- Basic knowledge of environment variables and JSON configuration.

### Steps to Host

1. **Create a project directory**
   ```bash
   mkdir Nickel-Auth
   cd Nickel-Auth
   ```

2. **Create docker-compose.yml file**
   ```bash
   nano docker-compose.yml
   ```
   
   Paste the following configuration:
   ```yaml
   services:
     nickel-auth:
       image: tfourj/nickel-auth:latest
       container_name: nickel-auth
       ports:
         - '3000:3000' # Use 127.0.0.1:3000:3000 if you want to use reverse proxy
       restart: unless-stopped
       volumes:
         - ./api_keys.json:/app/api_keys.json:ro
         - ./banned-ips.log:/app/banned-ips.log
       env_file: ".env"
       labels:
         - com.centurylinklabs.watchtower.enable=true
         - com.centurylinklabs.watchtower.scope=nickel-auth

     watchtower-nickel-auth:
       image: containrrr/watchtower
       container_name: watchtower-nickel-auth
       volumes:
         - /var/run/docker.sock:/var/run/docker.sock
       command: --cleanup --interval 300 --scope nickel-auth
       restart: unless-stopped
   ```

3. **Create environment configuration file**
   ```bash
   nano .env
   ```
   
   Add your configuration (replace with your actual values):
   ```env
   JWT_SECRET=your-super-secure-jwt-secret-here
   APPLE_TEAM_ID=your-apple-team-id
   APPLE_BUNDLE_ID=your.app.bundle.id
   PORT=3000
   RATE_LIMIT=50
   CHALLENGE_CACHE_TTL=300
   AUTH_CACHE_TTL=600
   NODE_ENV=production
   MONITORING_ORIGIN=http://example.com or false
   ```

4. **Create API keys configuration file**
   ```bash
   nano api_keys.json
   ```
   
   Add your Cobalt API endpoints and keys:
   ```json
   {
     "https://cobalt-api.example.com": "your-api-key-here",
     "https://another-cobalt-instance.com": "another-api-key"
   }
   ```

5. **Start the services**
   ```bash
   docker-compose up -d
   ```

6. **Verify the server is running**
   ```bash
   docker-compose logs -f nickel-auth
   ```
   
   The server should be accessible at `http://your-server-ip:3000`

### Configuration Details

#### Required Environment Variables
- `JWT_SECRET`: A secure random string for signing JWT tokens
- `APPLE_TEAM_ID`: Your Apple Developer Team ID (required for AppAttest)
- `APPLE_BUNDLE_ID`: Your app's bundle identifier

#### Optional Environment Variables
- `PORT`: Server port (default: 3200)
- `RATE_LIMIT`: Maximum requests per IP per time window (default: 50)
- `CHALLENGE_CACHE_TTL`: Challenge expiration time in seconds (default: 300)
- `AUTH_CACHE_TTL`: Authentication token expiration time in seconds (default: 600)
- `NODE_ENV`: Set to `production` for production deployment
- `MONITORING_ORIGIN`: CORS origin for metrics endpoint (default: false)

#### API Keys Configuration
The `api_keys.json` file maps Cobalt API server URLs to their respective authentication keys. Each entry should be in the format:
```json
{
  "https://cobalt-server-url": "api-key-for-that-server"
}
```

### Monitoring
- Access Prometheus metrics at `/metrics` endpoint
- Monitor container logs: `docker-compose logs -f`
- Check container status: `docker-compose ps`

### Updating
The Watchtower service automatically updates the container when new versions are released. You can also manually update:
```bash
docker-compose pull
docker-compose up -d
```

## License
This project is licensed under the GPU License. See the LICENSE file for details.
