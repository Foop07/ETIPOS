import { copyFileSync, mkdirSync } from 'node:fs'
import { dirname, resolve } from 'node:path'

const source = resolve('node_modules/webtorrent/dist/webtorrent.min.js')
const destination = resolve('../static/vendor/webtorrent.min.js')
mkdirSync(dirname(destination), { recursive: true })
copyFileSync(source, destination)
console.log(`Copied WebTorrent browser client to ${destination}`)
