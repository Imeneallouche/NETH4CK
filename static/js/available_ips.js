document.addEventListener("DOMContentLoaded", function () {
  var socket = io.connect(
    "http://" + window.location.hostname + ":" + window.location.port
  );

  socket.on("occupied_ip", function (data) {
    var ul = document.getElementById("occupied_ips");
    var li = document.createElement("li");
    li.appendChild(document.createTextNode(data.ip));
    ul.appendChild(li);
  });

  // Emit a message to start scanning for IPs
  var params = new URLSearchParams(window.location.search);
  var gateway_ip = params.get("gateway_ip");

  socket.emit("start_ip_scan", {
    gateway_ip: gateway_ip,
  });
});
