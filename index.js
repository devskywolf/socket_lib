var express = require('express');
var fs = require('fs');
var app = express();
var https = require('https');
var options = {
  key: fs.readFileSync('./cert/key.pem'),
  cert: fs.readFileSync('./cert/cert.crt')
};
var server = https.createServer(options, app);
// var io = require('socket.io')(server, { origins: '*:*'});
app.use(express.static('views'));
app.use(express.urlencoded({ extended: true }))
app.use(express.json());

var port = process.env.PORT || 3000;
server.listen(port, () => {
  console.log('Server listening at port %d', port);
});

var io = require('socket.io-client');
var { SocketExt } = require('./lib/socketlib.js');

const SOCKETIO_URL = "wss://localhost:4000";

// var socketLib = new SocketLib(io, port, "123456789");
// socketLib.bind('ss_newconnection', function(socket, channelName, data) {
//   var clientKey = data.client_key;
//   var serverKey = data.server_key;
//   return true;
// });

// socketLib.bind('disconnect', function(socket, channelName) {
//   socketLib.sendData(socket, channelName, 'user_disconnect', {
//     'type': 'user_left',
//     'username': socket.username,
//     'numConnects': 1
//   });
//   return false;
// });

// socketLib.bind('add_user', function(socket, channelName, data) {
//   socket.username = data.username;
  
//   socketLib.sendData(socket, channelName, 'login', {
//     'type': 'login',
//     'numUsers': 1
//   });
//   socketLib.sendData(socket, channelName, 'user_joined', {
//     'type': 'user_joined',
//     'username': socket.username,
//     'numUsers': 1
//   });

//   return false;
// });

// socketLib.bind('typing', function(socket, channelName, data) {
//   return true;
//   // socketLib.sendData(socket, channelName, 'typing', data);
// });

// socketLib.bind('stop_typing', function(socket, channelName, data) {
//   return true;
//   // socketLib.sendData(socket, channelName, 'stop_typing', data);
// });

// socketLib.bind('message', function(socket, channelName, data) {
//   // socketLib.sendData(socket, channelName, 'message', data);
//   return true;
// });
// socketLib.listen();

app.post('/message', function (req, res) {
  var socketExt = new SocketExt(io, SOCKETIO_URL, true);
  socketExt.setKeys('server_pub_id', '123456789', '123', '456');

  var body = req.body;
  var channelName = body.channelName;
  var channel = socketExt.subscribe(channelName);
  var msgName = body.msgName;
  var data = body.data;
  switch(msgName) {
    case 'message':
      channel.sendData('message', data);
      break;
    case 'typing':
      channel.sendData('typing', data);
      break;
    case 'stop_typing':
      channel.sendData('stop_typing', data);
      break;
    case 'add_user':
      username = data.username;
      var channelUser = socketExt.subscribe(username);
      channelUser.sendData('login', {
        'type': 'login',
      });
      channel.sendData('user_joined', {
        'type': 'user_joined',
        'username': data.username
      });
      break;
  }
  res.send('ok');
});
