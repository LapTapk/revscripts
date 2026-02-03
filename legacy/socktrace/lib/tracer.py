import json
import time
from pathlib import Path
import os

JS_REL_PATH = 'js/agent.js'
JS_PATH = f'{Path(__file__).parent.parent}/{JS_REL_PATH}'

class Tracer:
    def __init__(self, agent_conf, device, om, attach, target, argv, env):
        self.agent_conf = agent_conf
        config_json = json.dumps(agent_conf)

        with open(JS_PATH, 'r') as f:
            agent_js = f.read()

        self.agent_js = agent_js % { 'cfg': config_json }
        self.device = device
        self.om = om
        self.attach = attach
        self.target = target
        self.argv = argv
        self.env = env

        if self.attach:
            self.pid = int(self.target)
        else:
            self.pid = None

        self.session = None


    def _set_env(self):
        for (k, v) in self.env.items():
            os.environ[k] = v

    def stop(self):
        try:
            if self.session is not None:
                self.session.detach()
        except Exception:
            pass

        try:
            if self.pid is not None:
                pass
        except Exception:
            pass
        self.om.close_all()

    def _on_message(self, message, data):
        try:
            if message.get("type") == "send":
                payload = message.get("payload", {})
                mtype = payload.get("type")
                if mtype in ("init", "ready", "open", "close", "error"):
                    self.om.write_event(payload)
                    if mtype == "close":
                        conn_id = payload.get("conn_id")
                        if conn_id:
                            self.om.close_conn(conn_id)

                elif mtype == "data":
                    self.om.write_event({k: payload.get(k) for k in payload.keys() if k != "path"} | {"path": payload.get("path")})
                    conn_id = payload.get("conn_id")
                    direction = payload.get("direction")
                    if conn_id and direction and data is not None:
                        self.om.write_data(conn_id, direction, data)
                else:
                    self.om.write_event({"type": "unknown", "payload": payload, "ts_host": time.time()})

            elif message.get("type") == "error":
                self.om.write_event({"type": "frida_error", "description": message.get("description"), "stack": message.get("stack")})
            else:
                self.om.write_event({"type": "frida_msg", "message": message})
        except Exception as e:
            try:
                self.om.write_event({"type": "host_exception", "error": str(e), "message": message.get("type")})
            except Exception:
                pass

        
    def start(self):
        if self.attach:
            session = self.device.attach(self.pid)
        else:
            if self.env is not None:
                self._set_env()

            prog = self.target
            argv = [prog] + (self.argv or [])
            self.pid = self.device.spawn(argv)
            session = self.device.attach(self.pid)

        script = session.create_script(self.agent_js)

        def on_message(message, data):
            self._on_message(message, data)

        script.on("message", on_message)
        script.load()

        if not self.attach:
            self.device.resume(self.pid)

