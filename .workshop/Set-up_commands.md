# Environment (venv kept outside the repo so the workspace stays clean)
python3 -m venv .venv-opentide
.venv-opentide/bin/pip install "opentide==0.16.0"
export PATH=/Users/remi/github/.venv-opentide/bin:$PATH
export SSL_CERT_FILE="$(python -c 'import certifi;print(certifi.where())')"

mkdir -p Hacklu2026_ws && cd Hacklu2026_ws
git init                                     # empty repo first; the CLI adapts to the worktree

opentide setup repo --path . --name "SOC Detections" --org "Example Corp" \
  --description "Detection engineering repository for Example Corp SOC" \
  --platform sentinel --platform splunk --yes
opentide setup platforms --path . --sentinel --splunk --yes
opentide setup ci github --path . --default-branch master --yes
opentide setup mcp --path . --claude-code --generic --yes
opentide setup skills --path . --claude-code --generic --all \
  --name "SOC Detections" --org "Example Corp" \
  --description "Detection engineering repository for Example Corp SOC" --yes
opentide setup hooks --path . --install --yes

opentide generate                            # exit 0
opentide validate --strict                   # exit 0

git checkout -b Step-1-set-up
