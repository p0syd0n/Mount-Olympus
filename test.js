const Socket = require('blockchain.info/Socket');

const mySocket = new Socket();
mySocket.onTransaction(function() {
  console.log(arguments);
});
