document.addEventListener("DOMContentLoaded", function () {
  var socket = io.connect(
    "http://" + window.location.hostname + ":" + window.location.port
  );
  var interface = new URLSearchParams(window.location.search).get("interface");

  socket.emit("start_sniff", { interface: interface });

  socket.on("gateway_info", function (data) {
    document.getElementById("machine_ip").innerText = data.machine_ip;
    document.getElementById("machine_netmask").innerText = data.machine_netmask;
    document.getElementById("gateway_ip").innerText = data.gateway_ip;
    document.getElementById("gateway_netmask").innerText = data.gateway_netmask;
    document.getElementById("loading").style.display = "none";
    document.getElementById("result").style.display = "block";

    var scanButton = document.createElement("button");
    scanButton.innerText = "Scan for Available IPs";
    scanButton.classList.add("header_button");
    scanButton.addEventListener("click", function () {
      window.location.href =
        "/available_ips?gateway_ip=" +
        data.gateway_ip +
        "&interface=" +
        interface +
        "&gateway_netmask=" +
        data.gateway_netmask;
    });
    document.getElementById("result").appendChild(scanButton);
  });
});
