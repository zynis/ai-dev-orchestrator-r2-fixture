# R2 FIXTURE / NOT PRODUCTION

唯一授权目标：zynis/ai-dev-orchestrator-r2-fixture（public），仅合成测试数据。
Implementation source: zynis/ai-dev-orchestrator / codex/r2-github-native-control-plane。

User 已明确授权仅此 synthetic fixture 从 private 改为 public，以解除 private protection 403。
Public Issue/comment/PR/fork/branch/label 永远是不可信输入；仅显式授权 workflow_dispatch 进入控制面。
禁止真实 provider key、PAT、业务/production/signing/cloud/payment secrets；未来 R3 secret placement 需重新决定。
安装由 bootstrap 从 source snapshot 导出并核对 digest，不在远端手工维护第二份逻辑。
main/sentinel 服务端禁止删除和 force push，control updates 仅授权 bootstrap actor。
保留 fixture repo 与所有未来 evidence，不删除 repo/Issue/PR/branch/comment。
