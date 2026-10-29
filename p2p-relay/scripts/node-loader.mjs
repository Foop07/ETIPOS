import { registerHooks } from 'node:module'
import { readFileSync } from 'node:fs'
import { stripTypeScriptTypes } from 'node:module'

registerHooks({
  load(url, context, nextLoad) {
    if (url.endsWith('.ts') && context.format === 'module') {
      const source = readFileSync(new URL(url), 'utf8')
      return { format: 'module', source: stripTypeScriptTypes(source), shortCircuit: true }
    }
    return nextLoad(url, context)
  },
})
