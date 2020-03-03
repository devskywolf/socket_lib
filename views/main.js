const SERVER_URL = "62.23.208.221";
// const SERVER_URL = "localhost";
const port = 80;
const SOCKETIO_URL = "ws://" + SERVER_URL + ":" + port;

var FADE_TIME = 150; // ms
var TYPING_TIMER_LENGTH = 400; // ms

var $window = $(window);
var $usernameInput = $('.usernameInput'); // Input for username
var $messages = $('.messages'); // Messages area
var $roomName = $('.roomname'); // Messages area
var $testArea = $('.testarea');

var $inputMessage = $('.inputMessage'); // Input message input box

var $loginPage = $('.login.page'); // The login page
var $chatPage = $('.chat.page'); // The chatroom page

var username;
var connected = false;
var typing = false;
var lastTypingTime;
var $currentInput = $usernameInput.focus();

var channelName = '';
var socketExt = null;
var channel = null;
var channelMine = null;

  const setUsername = () => {
    username = cleanInput($usernameInput.val().trim());
    channelName = $("#roomname").val();
    socketExt = new SocketExt (null, SOCKETIO_URL, true);
    socketExt.setKeys(username, '123456789', '123');
    channel = socketExt.subscribe(channelName);

    channel.bind('newconnection_err', () => {
      console.log("connection error");
    });

    channel.bind('message', (data) => {
      addChatMessage(data);
    });

    channel.bind('user_joined', (data) => {
      log(data.username + ' joined into ' + channelName);
    });

    channel.bind('user_left', (data) => {
      log(data.username + ' left');
      addParticipantsMessage(data);
      removeChatTyping(data);
    });

    channel.bind('typing', (data) => {
      addChatTyping(data);
    });

    channel.bind('stop_typing', (data) => {
      removeChatTyping(data);
    });

    channel.bind('ss_disconnect_me', () => {
      log('you have been disconnected');
    });

    channel.bind('ss_disconnect', (data) => {
      userPubId = data.user_pub_id;
      log(userPubId + ' has been disconnected');
    });

    channel.bind('ss_newconnection', (data) => {
      var userPubId = data.user_pub_id;
      connected = true;
      if (username === userPubId) {
        postMessage('add_user', channelName, {'username':username});
      }
    });

    channel.bind('reconnect_error', () => {
      log('attempt to reconnect has failed');
    });
    if (username) {
      $loginPage.fadeOut();
      $chatPage.show();
      $loginPage.off('click');
    }
  }

  const sendMessage = () => {
    var message = $inputMessage.val();
    message = cleanInput(message);
    if (message && connected) {
      $inputMessage.val('');
      postMessage('message', channelName, {'username': username, 'message':message});
    }
  }

  const log = (message, options) => {
    var $el = $('<li>').addClass('log').text(message);
    addMessageElement($el, options);
  }

  const addChatMessage = (data, options) => {
    var $typingMessages = getTypingMessages(data);
    options = options || {};
    if ($typingMessages.length !== 0) {
      options.fade = false;
      $typingMessages.remove();
    }

    var $usernameDiv = $('<span class="username"/>')
      .text(data.username)
      .css('color', getUsernameColor(data.username));
    var $messageBodyDiv = $('<span class="messageBody">')
      .text(data.message);

    var typingClass = data.typing ? 'typing' : '';
    var $messageDiv = $('<li class="message"/>')
      .data('username', data.username)
      .addClass(typingClass)
      .append($usernameDiv, $messageBodyDiv);

    addMessageElement($messageDiv, options);
  }

  const addChatTyping = (data) => {
    data.typing = true;
    data.message = 'is typing';
    addChatMessage(data);
  }

  const removeChatTyping = (data) => {
    getTypingMessages(data).fadeOut(function () {
      $(this).remove();
    });
  }

  const addMessageElement = (el, options) => {
    var $el = $(el);

    if (!options) {
      options = {};
    }
    if (typeof options.fade === 'undefined') {
      options.fade = true;
    }
    if (typeof options.prepend === 'undefined') {
      options.prepend = false;
    }

    if (options.fade) {
      $el.hide().fadeIn(FADE_TIME);
    }
    if (options.prepend) {
      $messages.prepend($el);
    } else {
      $messages.append($el);
    }
    $messages[0].scrollTop = $messages[0].scrollHeight;
  }

  const cleanInput = (input) => {
    return $('<div/>').text(input).html();
  }

  const updateTyping = () => {
    if (connected) {
      if (!typing) {
        typing = true;
        postMessage('typing', channelName, {username: username});
      }
      lastTypingTime = (new Date()).getTime();

      setTimeout(() => {
        var typingTimer = (new Date()).getTime();
        var timeDiff = typingTimer - lastTypingTime;
        if (timeDiff >= TYPING_TIMER_LENGTH && typing) {
          postMessage('stop_typing', channelName, {username: username});
          typing = false;
        }
      }, TYPING_TIMER_LENGTH);
    }
  }

  const getTypingMessages = (data) => {
    return $('.typing.message').filter(function (i) {
      return $(this).data('username') === data.username;
    });
  }

  // Gets the color of a username through our hash function
  const getUsernameColor = (username) => {
    return 5; 
  }

  $window.keydown(event => {
    if (!(event.ctrlKey || event.metaKey || event.altKey)) {
    }
    if (event.which === 13) {
      if (username) {
        sendMessage();
        postMessage('stop_typing', channelName, {username:username});
        typing = false;
      } else {
        setUsername();
      }
    }
  });

  $inputMessage.on('input', () => {
    updateTyping();
  });

  function postMessage(msgName, channelName, data) {
    var data = {
      msgName: msgName,
      channelName: channelName,
      data: data
    }
    $.ajax({
      url : "message",
      type: "POST",
      data : data,
      header: {'Content-Type': 'application/json'},
      success: function(data, textStatus, jqXHR)
      {},
      error: function (jqXHR, textStatus, errorThrown)
      {}
    });

    // channel.sendData(msgName, data);
  }

  function displayTestResult(type, size, data) {
    console.log(data);
    console.log(type + "---" + size);
  }