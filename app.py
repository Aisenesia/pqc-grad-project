"""
Crypto Network Application Launcher
Starts the server and opens the web interface
"""
import asyncio
import webbrowser
import time
from pathlib import Path
import sys

# Import server module
sys.path.insert(0, str(Path(__file__).parent))
import server

def main():
    print("=" * 60)
    print("   CRYPTO NETWORK VISUALIZER")
    print("=" * 60)
    print()
    print("Starting server...")
    print(f"  TCP Server: 127.0.0.1:{server.TCP_PORT}")
    print(f"  WebSocket: 127.0.0.1:{server.WS_PORT}")
    print()
    print("Opening visualizer in browser...")
    
    # Open browser after a short delay
    dashboard_path = Path(__file__).parent / 'dashboard' / 'visualizer.html'
    dashboard_url = f'file:///{dashboard_path.as_posix()}'
    
    def open_browser():
        time.sleep(1)
        webbrowser.open(dashboard_url)
    
    import threading
    threading.Thread(target=open_browser, daemon=True).start()
    
    # Start server
    try:
        asyncio.run(server.main())
    except KeyboardInterrupt:
        print("\n\nShutting down...")
        # Clean up any running client processes
        for proc in server.state.client_processes:
            try:
                proc.terminate()
            except:
                pass
        print("Server stopped.")

if __name__ == "__main__":
    main()
