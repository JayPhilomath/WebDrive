
# WebDrive

WebDrive is a simple, lightweight way to share files between devices on the same local network. 

Launch WebDrive on one computer, then open the displayed IP address on another device connected to the same network. From the browser, you can upload files into the shared folder and download them again from any connected device.

![WebDrive main page](images/webdrive-main-page.png)

## Basic Usage

1.  Launch `WebDrive.exe`.
    
2.  Note the local IP address displayed by the application.
    
3.  Open that address in a browser on another device connected to the same network.
    
4.  Upload or download files through the web interface.
    

For example:

```text
http://192.168.1.25:8000

```

The exact address will depend on your computer and local network.

![WebDrive server startup window](images/webdrive-server-startup.png)

### Command-Line Options

WebDrive can be configured using command-line options.

```bash
WebDrive.exe --dir "C:\Shared Files" --port 8000

```
#### Commands:

| Option | Value | Description |
|---|---|---|
| `-h`, `--help` | — | Show the help message and exit. |
| `--dir` | `DIRECTORY` | Directory to serve. Defaults to a `shared` folder beside the application, which is created if missing. |
| `--host` | `HOST` | Host address to bind the server to. |
| `--port` | `PORT` | Port on which to run the server. |
| `--password` | `PASSWORD` | Optional browser access password. Prefer `--password-file` on shared systems. |
| `--password-file` | `PASSWORD_FILE` | Optional file containing the browser access password. |
| `--max-upload-mb` | `MAX_UPLOAD_MB` | Maximum upload size per request, in MB. Default: `1024`. |
| `--disable-change-root` | — | Disable changing the shared folder through the browser interface. |
| `--cert` | `CERT_FILE` | Optional TLS certificate file used to enable HTTPS. |
| `--key` | `KEY_FILE` | Optional TLS private key file used to enable HTTPS. |
| `--threads` | `THREADS` | Number of worker threads used by the HTTP server. Default: `16`. |



### Shared Folder

By default, WebDrive creates and serves a folder named `shared` beside the application.

You can select another folder when starting the application:

```bash
WebDrive.exe --dir "D:\WebDrive"

```

To prevent the shared folder from being changed through the browser interface, use:

```bash
WebDrive.exe --dir "D:\WebDrive" --disable-change-root

```

### Password Protection

Browser access can optionally be protected with a password:

```bash
WebDrive.exe --password "example-password"

```

On a shared computer, using a password file is preferable because the password will not appear directly in the command history or process arguments:

```bash
WebDrive.exe --password-file "password.txt"

```

The password file should contain the browser access password.

![WebDrive password prompt](images/webdrive-password-prompt.png)

#### HTTPS

WebDrive can serve files over HTTPS when provided with a TLS certificate and private key:

```bash
WebDrive.exe --cert "certificate.pem" --key "private-key.pem"

```

WebDrive does not automatically create or manage certificates. You are responsible for supplying appropriate certificate files.

For ordinary use on a trusted home network, HTTP may be sufficient. HTTPS is preferable when traffic could be observed by other devices on the network.

### Upload Limits

The default maximum upload size is `1024 MB` per request.

You can change this limit with:

```bash
WebDrive.exe --max-upload-mb 2048

```

## Development Background

I originally created a much smaller version of this project in 2018 for personal convenience. Simply to make transferring files between my local devices easier to do. 

The current version includes several additions suggested or partially developed with the assistance of AI tools, including:

-   Password protection
    
-   Optional HTTPS support
    
-   Maximum upload-size controls
    
-   Configurable HTTP worker threads
    

Some of the newer networking and security-related code extends beyond what I can independently reviewed as I lack a thorough understanding of networking.

**AI assistance is disclosed here** because contributions that simplify the implementation, remove unnecessary features, identify security problems, or replace questionable additions with more technically correct approaches are not just welcome, but appreciated for my ongoing learning.

This remains primarily a *convenience* project.

### Security Notice

WebDrive is for use on trusted local networks. Avoid exposing it directly to the public internet unless you understand the associated security considerations. 

When using WebDrive:

-   Enable password protection when other people share the network.
    
-   Use `--password-file` instead of `--password` on shared systems.
    
-   Use HTTPS if network traffic needs to be encrypted.
    
-   Avoid sharing folders containing sensitive or unrelated files.


# Contributions
Bug reports, security observations, documentation fixes, and technically grounded improvements are welcome. Please explain the reason for significant technical changes so that I can learn why something is changed. 


