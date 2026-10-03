(function () {
  var socket, retry, stopped = false, delay = 1000;
  function canConnect() {
    return !stopped && !document.hidden;
  }
  function disconnect() {
    clearTimeout(retry);
    retry = null;
    if (socket) {
      var current = socket;
      socket = null;
      current.onopen = current.onclose = current.onerror = null;
      current.close(1000, 'inactive');
    }
  }
  function reconnect() {
    if (!canConnect()) return;
    clearTimeout(retry);
    retry = setTimeout(connect, delay + Math.random() * 1000);
    delay = Math.min(delay * 2, 30000);
  }
  function connect() {
    if (!canConnect() || socket) return;
    clearTimeout(retry);
    retry = null;
    try {
      var current = new WebSocket((location.protocol === 'https:' ? 'wss://' : 'ws://') + location.host + '/_expose/presence');
      socket = current;
      // Browsers answer the server's WebSocket ping frames automatically,
      // while visibility events disconnect tabs that are no longer visible.
      current.onopen = function () { if (socket === current) delay = 1000; };
      current.onclose = function () {
        if (socket !== current) return;
        socket = null;
        reconnect();
      };
      current.onerror = function () { if (socket === current) current.close(); };
    } catch (_) {
      socket = null;
      reconnect();
    }
  }
  addEventListener('pagehide', function () {
    stopped = true;
    disconnect();
  });
  addEventListener('pageshow', function () { stopped = false; connect(); });
  document.addEventListener('visibilitychange', function () {
    if (document.hidden) disconnect();
    else connect();
  });
  connect();
})();
