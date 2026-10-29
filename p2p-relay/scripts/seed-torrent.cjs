import fs from 'node:fs'
const filePath = process.argv[2]
const torrentBuffer = Buffer.from(process.argv[3], 'base64')
async function main () {
  const { default: WebTorrent } = await import('webtorrent')
  const client = new WebTorrent({ dht: false, tracker: true })
  const parsed = await (await import('parse-torrent')).default(torrentBuffer)
  const announce = Array.isArray(parsed.announce) ? parsed.announce[0] : parsed.announce
  client.seed(filePath, { torrent: torrentBuffer, announce: announce ? [announce] : [] }, (torrent) => {
    console.log(`Seeding ${torrent.infoHash}`)
  })
  function close () {
    client.destroy(() => process.exit(0))
  }
  process.on('SIGINT', close)
  process.on('SIGTERM', close)
  setInterval(() => {
    if (!fs.existsSync(filePath)) close()
  }, 5000).unref()
}
main().catch((error) => {
  console.error(error)
  process.exit(1)
})
