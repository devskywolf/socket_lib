
var express = require('express');
var fs = require('fs');
var app = express();
var https = require('https');
var options = {
  key: fs.readFileSync('./cert/key.pem'),
  cert: fs.readFileSync('./cert/cert.crt'),
};
var server = https.createServer(options, app);
// var server = require('http').createServer(app);
var io = require('socket.io')(server, {
    origins: '*:*',
    path : '/socket_server'
  });
var { SocketLib, SocketExt } = require('./lib/socketlib.js');

app.use(express.static('views'));
app.use(express.urlencoded());
app.use(express.json());

var port = process.env.PORT || 4000;

server.listen(port, () => {
  console.log('Server listening at port %d', port);
});

var socketLib = new SocketLib(io, port, "123456789");
socketLib.bind('ss_newconnection', function(socket, channelName, data) {
  var clientKey = data.client_key;
  var serverKey = data.server_key;
  return true;
});

socketLib.bind('ss_disconnect', function(socket, channelName) {
  return true;
});

socketLib.bind('add_user', function(socket, channelName, data) {
  socket.username = data.username;
  
  socketLib.sendData(socket, channelName, 'login', {
    'type': 'login',
    'numUsers': 1
  });
  socketLib.sendData(socket, channelName, 'user_joined', {
    'type': 'user_joined',
    'username': socket.username,
    'numUsers': 1
  });

  return false;
});

socketLib.bind('typing', function(socket, channelName, data) {
  return true;
  // socketLib.sendData(socket, channelName, 'typing', data);
});

socketLib.bind('stop_typing', function(socket, channelName, data) {
  return true;
  // socketLib.sendData(socket, channelName, 'stop_typing', data);
});

socketLib.bind('message', function(socket, channelName, data) {
  // socketLib.sendData(socket, channelName, 'message', data);
  return true;
});
socketLib.listen();


