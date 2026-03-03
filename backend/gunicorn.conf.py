import sys

preload_app = False
loglevel = "info"
capture_output = True
errorlog = "-"
accesslog = "-"

def post_fork(server, worker):
    print(f"[GUNICORN] Worker forked (pid: {worker.pid})", file=sys.stderr, flush=True)

def post_worker_init(worker):
    print(f"[GUNICORN] Worker ready (pid: {worker.pid})", file=sys.stderr, flush=True)

def worker_exit(server, worker):
    print(f"[GUNICORN] Worker exiting (pid: {worker.pid})", file=sys.stderr, flush=True)

def worker_abort(worker):
    print(f"[GUNICORN] Worker ABORT (pid: {worker.pid})", file=sys.stderr, flush=True)
