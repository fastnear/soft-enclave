/**
 * Yarn constraints
 * Automatically syncs version across all workspace packages
 */
module.exports = {
  async constraints({ Yarn }) {
    const projectRootMonorepo = Yarn.workspace()
    const rootVersion = projectRootMonorepo.manifest.version

    // Sync all workspace versions with root
    for (const workspace of Yarn.workspaces()) {
      if (!workspace.ident.startsWith('@near/soft-enclave')) {
        continue
      }
      workspace.set('version', rootVersion)
    }
  },
}
