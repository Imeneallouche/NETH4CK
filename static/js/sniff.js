var socket = io.connect(
  "http://" + window.location.hostname + ":" + window.location.port
);
socket.on("gateway_info", function (data) {
  document.getElementById("machine_ip").innerText = data.machine_ip;
  document.getElementById("machine_netmask").innerText = data.machine_netmask;
  document.getElementById("gateway_ip").innerText = data.gateway_ip;
  document.getElementById("gateway_netmask").innerText = data.gateway_netmask;
  document.getElementById("loading").style.display = "none";
  document.getElementById("result").style.display = "block";
});
