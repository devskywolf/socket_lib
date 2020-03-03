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

const SERVER_URL = "localhost";
const port = process.env.PORT || 3000;
const SOCKETIO_URL = "wss://" + SERVER_URL + ":" + port;
server.listen(port, () => {
  console.log('Server listening at port %d', port);
});


//**************************************************************************************//
//*                                                                                     //
//*                                   SocketIO Server                                   //
//*                                                                                     //
//**************************************************************************************//

var io_server = require('socket.io')(server, {origins: '*:*',path : '/socket_server'});
var { SocketLib, DATA_TYPE } = require('./lib/socketlib.js');

var socketLib = new SocketLib(io_server, "123456789");
//When some user is connected to the SocketLibServer
//If return value is true, caller send default message to other clients.
//If else, caller don't send message to other.
socketLib.bind('ss_newconnection', function(socket, channelName, data) {
  //Confirm the clientKey and the serverKey. 
  //When newconnection is only received from the httpServer, serverKey is existed.
  var userPubId = data.userPubId;
  var clientKey = data.client_key;
  var serverKey = data.server_key;
  if (clientKey !== '123') {
    socketLib.sendDataToSender(socket, channelName, 'newconnection_err', {}, DATA_TYPE.JSON);
    return false;
  }
  //  If you want to send a message to the clients in here, add a code with                                 */
  //   parameters: socket, channelName, mesageName, data, dataType in here.                                 */
  //  Ex. socketLib.sendData(socket, channelName, 'new_connected', {'type': 'login'}, DATA_TYPE.JSON);      */
  return true;
});

//When some user is disconnected from the SocketLibServer
socketLib.bind('ss_disconnect', function(socket, channelName) {
  return true;
});

//*                            For Custom messages                                */
//* If you don't have any functions for the custom messages in here,              */
//*   the caller automatically sends the sender's message to other clinets.       */
//* This is the same as when the return value is true.                            */
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
});

socketLib.bind('stop_typing', function(socket, channelName, data) {
  return true;
});

socketLib.bind('message', function(socket, channelName, data) {
  return true;
});

//Add the listen caller after the bind funtions is defined
socketLib.listen();




//**************************************************************************************//
//*                                                                                     //
//*                      HTTPS Server and SocketIO Client                               //
//*                                                                                     //
//**************************************************************************************//
var io = require('socket.io-client');
var { SocketExt } = require('./lib/socketlib.js');

app.post('/message', function (req, res) {
  var socketExt = new SocketExt(io, SOCKETIO_URL, true);
  socketExt.setKeys('server_pub_id', '123456789', '123', '456');

  var body = req.body;
  var channelName = body.channelName;
  var channel = socketExt.subscribe(channelName);

  //If you want to recevie the 'message' named messages from the channel, 
  //  you can use the function like the example bellow.
  channel.bind('message', (data) => {
    //console.log(data);
  });

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
