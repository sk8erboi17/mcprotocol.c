'use strict'

const path = require('path')

function fail (message) {
  process.stderr.write(`${message}\n`)
  process.exit(1)
}

if (process.argv.length !== 8) {
  fail(`usage: ${process.argv[1]} module-root mode host port clients messages`)
}

const moduleRoot = path.resolve(process.argv[2])
const minecraftProtocol = require(path.join(moduleRoot, 'minecraft-protocol'))
const mode = process.argv[3]
const host = process.argv[4]
const port = Number(process.argv[5])
const clientCount = Number(process.argv[6])
const messageCount = Number(process.argv[7])

if (!['login', 'stream', 'concurrent'].includes(mode) || !Number.isInteger(port) || port < 1 || port > 65535 ||
    !Number.isInteger(clientCount) || clientCount < 1 || !Number.isInteger(messageCount) || messageCount < 1 ||
    (mode === 'stream' && clientCount !== 1)) {
  fail('invalid benchmark arguments')
}

let completed = 0
let failed = false
const started = process.hrtime.bigint()

function finishOne () {
  completed++
  if (completed === clientCount) {
    const elapsed = process.hrtime.bigint() - started
    const operations = mode === 'login' ? clientCount : clientCount * messageCount
    process.stdout.write(JSON.stringify({ elapsed_ns: Number(elapsed), operations }) + '\n')
  } else if (mode === 'login') {
    createOne()
  }
}

function createOne () {
  const client = minecraftProtocol.createClient({
    host,
    port,
    username: 'BenchmarkClient',
    version: '1.8.8',
    auth: 'offline',
    hideErrors: true
  })
  let packets = 0
  let joined = false

  client.on('error', error => {
    if (failed) return
    failed = true
    fail(`Node client failed: ${error.message}`)
  })

  client.once('playerJoin', () => {
    joined = true
    if (mode === 'login') {
      client.end('benchmark complete')
    }
  })

  client.on('keep_alive', () => {
    packets++
  })

  client.once('end', () => {
    if (mode === 'login') {
      if (!joined) fail('Node client ended before login completed')
      finishOne()
      return
    }
    if (!joined || packets !== messageCount) {
      fail(`Node client ended after ${packets}/${messageCount} validated keep-alives`)
    }
    finishOne()
  })
}

if (mode === 'login') {
  createOne()
} else {
  for (let index = 0; index < clientCount; index++) createOne()
}
