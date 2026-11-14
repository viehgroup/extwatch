# extwatch

Catch backdoored VS Code, Cursor and Windsurf extensions.

```
$ extwatch demo-backdoored.vsix

demo.demo-ext@1.0.0 (vsix file)
  high   EW007  Code injected before the bundle
    1,222 characters of code run before the bundler's own header
    and use: authorized_keys, child_process, env_harvest,
    launch_agent, public_ip_ip, reverse_tunnel
    [dist/extension.js @0]
    fix: Compare this file with the official release. This is
         how the Oct 2026 Claude Code extension backdoor was
         inserted.
  high   EW001  Plants SSH keys
  high   EW003  Reverse SSH tunnel
  ... (details for 5 more findings omitted here)

1 extension scanned: 6 high, 1 medium
```

## Why

Editor extensions run with your full user permissions: your source code, SSH keys,
cloud credentials, all of it. And they update themselves.

In 2026 that went wrong twice in public:

- **May:** GitHub confirmed a breach of about 3,800 repositories that started with a
  malicious VS Code extension.
- **October:** the Claude Code extension served by the Cursor Marketplace (versions
  2.1.312 and 2.1.313) carried a backdoor. It added an attacker's key to
  `~/.ssh/authorized_keys`, opened a reverse SSH tunnel, installed a LaunchAgent or cron
  job to survive reboots, and sent home a list of secret-looking environment variables.
  The code was pasted in front of an otherwise normal bundle, so it ran before the
  extension even activated. ([Phorion's write-up](https://phorion.io/blog/offical-claude-code-vsx-compromise/))

Most people never look inside their extensions. extwatch does it for you.

## Quick start

```
pip install git+https://github.com/viehgroup/extwatch
extwatch                    # scan every installed extension
extwatch --verify           # also compare with official releases
extwatch --hunt             # also look for backdoor leftovers
```

No dependencies. Works on macOS, Linux and Windows.

It finds extensions for VS Code, VS Code Insiders, VSCodium, Cursor, Windsurf, Trae, Kiro,
Positron, and remote servers (`~/.vscode-server`, `~/.cursor-server`).

## What it checks

**Behaviour.** It reads each extension's code and looks for combinations that honest
extensions don't need: writing to `authorized_keys`, reverse SSH tunnels, LaunchAgents,
cron jobs and startup scripts, code hidden behind `eval(atob(...))`, connections to raw IP
addresses, harvesting secret environment variables, and code injected ahead of the bundle.

Single signals are ignored on purpose. Git, Docker and Python extensions all spawn
processes; that alone means nothing.

**Official release (`--verify`).** It downloads the same version from the VS Marketplace
or Open VSX and compares every file. A file that differs from what the publisher shipped
is the strongest signal there is, and it's exactly what would have exposed the October
backdoor. Packages are cached in `~/.cache/extwatch`.

When an extension matches a verified publisher's release byte for byte, weak hints are
dropped. High-severity behaviour still shows, because a publisher's own build can be
compromised too.

**Identity.** Lookalikes of popular extensions (same display name, same name from another
publisher, or an ID one character off), extensions installed from a file, versions that
have been pulled from the marketplaces, and published indicators of compromise.

**Leftovers (`--hunt`).** Uninstalling a backdoored extension doesn't undo what it did.
Hunt mode checks for known attacker SSH keys, recently changed `authorized_keys`,
LaunchAgents pretending to be Apple, `@reboot` cron jobs and user services running hidden
scripts, Windows Startup scripts, files from known incidents, and live reverse SSH tunnels.
It only reads; it never changes or deletes anything.

## Scan before you install

```
extwatch some-extension.vsix
```

## For extension authors

Check your own build before you publish it, so a compromised build machine or dependency
can't slip something into your release:

```yaml
- run: npx @vscode/vsce package -o my-extension.vsix
- uses: viehgroup/extwatch@main
  with:
    vsix: my-extension.vsix
    fail-on: high
```

Pin the action to a commit SHA in production workflows.

## Options

```
extwatch [paths...] [--verify] [--hunt] [--editor NAME]
         [--only ID] [--format text|json|sarif|github]
         [-o FILE] [--fail-on high|medium|low|never]
         [--ignore RULE] [--list-rules]
```

Exit code is `1` when anything at or above `--fail-on` (default `high`) is found.
`--format json` works well for scanning many machines from a management tool.

## Rules

| ID | What it means |
|---|---|
| EW001 | Writes to `~/.ssh/authorized_keys` |
| EW002 | Creates a LaunchAgent, cron job, startup script or user service |
| EW003 | Opens a reverse SSH tunnel, or runs ssh in the background with host checks off |
| EW004 | Reads credential stores (cloud credentials, browser logins, keychain) |
| EW005 | Decodes and executes a hidden payload |
| EW006 | Connects to a hard-coded public IP address |
| EW007 | Code sits in front of the bundler's header and runs before activation |
| EW008 | Pipes a download into a shell |
| EW009 | References a service commonly used to receive stolen data |
| EW010 | Collects secret-looking environment variables |
| EW011 | Looks up the machine's public IP and reports it |
| EW012 | Files differ from the official marketplace release |
| EW013 | Version is no longer on the official marketplaces |
| EW014 | Not listed on any public marketplace |
| EW015 | Matches a published indicator of compromise |
| EW016 | Imitates a popular extension |
| EW017 | Installed manually from a `.vsix` |
| EW018 | Installed or updated in the last week (context for other findings) |
| EW020–EW027 | Hunt mode: attacker keys, known backdoor files, fake LaunchAgents, boot tasks, Startup scripts, live tunnels |

Run `extwatch --list-rules` for the full descriptions.

## How it was tested

- **The October backdoor.** An inert recreation with the same structure (injected
  prefix, SSH key planting, reverse tunnel, LaunchAgent, environment harvesting, beacon)
  is caught on every behaviour, plus the published version indicator when it's
  installed in Cursor. The recreation throws on its first line, uses a dummy key and a
  reserved test address; build it with `python examples/make_demo.py`.
- **Real extensions.** 18 official builds downloaded from their GitHub releases,
  including Cline, Continue, rust-analyzer, Go, Java, Prettier, YAML, Deno and Vim:
  no high or medium findings. Three low notes, all accurate (Cline reads Google Cloud
  credentials for Vertex AI; Julia shows an installer command).
- **Marketplace comparison.** The VS Marketplace copy of the YAML extension 2.0.0 is
  byte-identical to its GitHub release, so an honest extension compares clean.
- **SSH fingerprints** match `ssh-keygen` for Ed25519 and RSA keys.
- 22 unit tests on Python 3.9, 3.11 and 3.13; CI also runs the action on the demo files.

```
python -m unittest discover -s . -p "test_*.py" -v
```

## Limits

- Behaviour checks are static pattern matching. A determined attacker can try to dodge
  them; `--verify` is the strongest protection and you should use it.
- `--verify` downloads every extension package, which takes a while the first time.
- If a publisher's own pipeline is compromised, the official release is compromised too,
  and the comparison will match. Behaviour checks still apply in that case.
- Hunt mode covers the common persistence spots, not every possible one. A clean result
  doesn't prove a machine is clean.
- extwatch reports; it never removes or changes anything.

## Related

From the same team:
[slopwatch](https://github.com/viehgroup/slopwatch) blocks hallucinated and typosquatted
packages, and [agentscan](https://github.com/viehgroup/agentscan) finds leaked keys and
risky settings in AI agent configs.

## License

MIT. Built and maintained by the **VIEH Security Team**.
