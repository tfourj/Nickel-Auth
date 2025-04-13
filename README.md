# Nickel-Auth

Nickel-Auth is a proxy server designed to facilitate authentication between the iOS app [Nickel](https://github.com/tfourj/Nickel) and the [Cobalt.Tools](https://github.com/imputnet/cobalt) API servers because Swift lacks current turnstile implementation that cobalt uses to secure their servers.

## Features
- Acts as a bridge between the Nickel app and Cobalt.Tools API.
- Uses Apple's AppAttest authentication method to authenticate server with app.
- Enables the **Nickel-Auth** feature in the Nickel app for seamless authentication.

## Adding Your Instance to Nickel App
If you'd like to add your instance to the Nickel app, please contact us at [support@tfourj.com](mailto:support@tffourj.com).

You can also view a list of public instances at [Nickel's Website](https://getnickel.site/instances).

## Self-Hosting Tutorial

### Prerequisites
- [Node.js](https://nodejs.org/) installed on your system.
- [Docker](https://www.docker.com/) and [Docker Compose](https://docs.docker.com/compose/) installed.

### Steps to Host

1. **Clone the Repository**
   ```bash
   git clone https://github.com/tfourj/Nickel-Auth.git
   cd Nickel-Auth
   ```

2. **Edit Configuration Files**
   - Update the `.env`(rename .example) file with your configuration.
   - Edit `api_keys.json`(rename .example) with the required API keys.

3. **Install Dependencies**
   ```bash
   npm install
   ```

4. **Run the Server**
   - **With Docker Compose**:
     - Ensure `docker-compose.yml` is properly configured.
     - Start the service:
       ```bash
       docker-compose up -d
       ```
   - **Manually with Node.js**:
     ```bash
     npm start
     ```

5. **Verify the Server**
   - The proxy server should now be running. Access it at `http://ip:<port>` (replace `<port>` with the configured port).

## License
This project is licensed under the GPU License. See the LICENSE file for details.
