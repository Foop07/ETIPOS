async function main () {
  const fs = await import('node:fs')
  const os = await import('node:os')
  const path = await import('node:path')
  const crypto = await import('node:crypto')
  const requestPath = process.argv[2]
  const request = JSON.parse(fs.readFileSync(requestPath, 'utf8'))
  const chunks = []
  for await (const chunk of process.stdin) chunks.push(chunk)
  const { default: createTorrent } = await import('create-torrent')
  const parseTorrent = (await import('parse-torrent')).default
  const payload = Buffer.concat(chunks)
  const dir = request.seed_dir || fs.mkdtempSync(path.join(os.tmpdir(), 'etipos-seed-'))
  fs.mkdirSync(dir, { recursive: true })
  const filename = path.basename(request.seed_name || request.filename || 'file')
  const filePath = path.join(dir, filename)
  const temporaryPath = `${filePath}.partial`
  fs.writeFileSync(temporaryPath, payload)
  fs.renameSync(temporaryPath, filePath)
  try {
    const createOptions = { name: filename, announceList: [[request.announce]], pieceLength: 256 * 1024 }
    const torrentBuffer = await new Promise((resolve, reject) => {
      createTorrent(filePath, createOptions, (error, torrent) => {
        if (error) reject(error)
        else resolve(torrent)
      })
    })
    const parsed = await parseTorrent(torrentBuffer)
    if (!parsed.announce?.includes(request.announce)) {
      throw new Error('Generated torrent is missing the configured tracker')
    }
    if (parsed.files.reduce((sum, file) => sum + file.length, 0) !== payload.length) {
      throw new Error('Generated torrent file length does not match scanned payload')
    }
    if (!parsed.infoHash || parsed.infoHash.length !== 40 || !parsed.files?.length || !parsed.files[0].length) {
      throw new Error('Generated torrent metadata is incomplete')
    }
    const expected = crypto.createHash('sha256').update(payload).digest('hex')
    const verified = await new Promise((resolve, reject) => {
      createTorrent(filePath, createOptions, (error, checkBuffer) => {
        if (error) reject(error)
        else resolve(checkBuffer)
      })
    })
    if (verified.length !== torrentBuffer.length || !Buffer.from(verified).equals(torrentBuffer)) {
      throw new Error('Generated torrent verification failed')
    }
    const torrent = Buffer.from(torrentBuffer).toString('base64')
    const magnetURI = `${parsed.magnetURI}&tr=${request.announce}`
    process.stdout.write(JSON.stringify({
      infoHash: parsed.infoHash,
      magnetURI,
      torrent,
      tempPath: filePath,
      tempDir: dir,
      sha256: expected,
    }))
  } catch (error) {
    fs.rmSync(dir, { recursive: true, force: true })
    process.stderr.write(String(error))
    process.exitCode = 1
  }
}
main().catch((error) => {
  process.stderr.write(String(error))
  process.exit(1)
})
