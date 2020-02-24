
var express = require('express');
var fs = require('fs');
var app = express();
var https = require('https');
var options = {
  key: fs.readFileSync('./cert/key.pem'),
  cert: fs.readFileSync('./cert/cert.crt'),
};
var server = https.createServer(options, app);
app.use(express.static('views'));
app.use(express.urlencoded({ extended: true }))
app.use(express.json());

var port = process.env.PORT || 4000;
server.listen(port, () => {
  console.log('Server listening at port %d', port);
});

var io = require('socket.io')(server, {origins: '*:*',path : '/socket_server'});
var { SocketLib, DATA_TYPE } = require('./lib/socketlib.js');

var socketLib = new SocketLib(io, "123456789");

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
  //**********************************************************************************************************/
  //*  If you want to send a message to the clients in here, add a code with                                 */
  //*   parameters: socket, channelName, mesageName, data, dataType in here.                                 */
  //*  Ex. socketLib.sendData(socket, channelName, 'new_connected', {'type': 'login'}, DATA_TYPE.JSON);      */
  //**********************************************************************************************************/
  return true;
});

//When some user is disconnected from the SocketLibServer
socketLib.bind('ss_disconnect', function(socket, channelName) {
  return true;
});

//*********************************************************************************/
//*                            For Custom messages                                */
//* If you don't have any functions for the custom messages in here,              */
//*   the caller automatically sends the sender's message to other clinets.       */
//* This is the same as when the return value is true.                            */
//*********************************************************************************/
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


