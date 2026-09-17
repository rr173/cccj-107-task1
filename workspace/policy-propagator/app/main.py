from .server import make_server

if __name__ == "__main__":
    import os
    srv = make_server(port=int(os.environ.get("PP_PORT", "8080")))
    print(f"[ctrl] listening on :{os.environ.get('PP_PORT', '8080')}",
          flush=True)
    srv.serve_forever()
