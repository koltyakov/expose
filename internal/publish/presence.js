(function () {
  var socket, retry, stopped = false, delay = 1000;
  function reconnect() {
    if (stopped) return;
    retry = setTimeout(connect, delay + Math.random() * 1000);
    delay = Math.min(delay * 2, 30000);
  }
  function connect() {
    if (stopped || socket) return;
    try {
      socket = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/_expose/presence');
      // Browsers answer the server's WebSocket ping frames automatically,
      // including when background-tab JavaScript timers are throttled.
      socket.onopen = function () { delay = 1000; };
      socket.onclose = function () { socket = null; reconnect(); };
      socket.onerror = function () { if (socket) socket.close(); };
    } catch (_) {
      socket = null;
      reconnect();
    }
  }
  addEventListener('pagehide', function () {
    stopped = true;
    clearTimeout(retry);
    if (socket) {
      socket.onclose = socket.onerror = null;
      socket.close();
      socket = null;
    }
  });
  addEventListener('pageshow', function () { stopped = false; connect(); });
  connect();
})();
