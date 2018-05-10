if (require('./requires-a-function')() !== 'loaded lol') {
  console.log('X - Fails to quibble with -r option')
  process.exit(1)
} else {
  console.log('✔️ - Able to use quibble with -r option')
}
