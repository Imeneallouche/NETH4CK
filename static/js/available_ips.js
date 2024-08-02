document.addEventListener("DOMContentLoaded", function () {
  var socket = io.connect(
    "http://" + window.location.hostname + ":" + window.location.port
  );
  var occupiedIps = [];
  var params = new URLSearchParams(window.location.search);
  var gateway_ip = params.get("gateway_ip");
  var interface = params.get("interface");
  var gateway_netmask = params.get("gateway_netmask");

  socket.on("occupied_ip", function (data) {
    occupiedIps.push(data.ip);
    var tbody = document.getElementById("occupied_ips_table");
    if (tbody) {
      var row;
      if (occupiedIps.length % 6 === 1) {
        row = document.createElement("tr");
        tbody.appendChild(row);
      } else {
        row = tbody.lastElementChild;
      }
      var cell = document.createElement("td");
      cell.textContent = data.ip;
      row.appendChild(cell);
    }
  });

  socket.on("scan_complete", function () {
    var buttonContainer = document.querySelector(".button-container");
    if (buttonContainer) {
      var showAvailableIpsButton = document.createElement("button");
      showAvailableIpsButton.innerText = "Discover Free IPs";
      showAvailableIpsButton.classList.add("header_button");
      showAvailableIpsButton.addEventListener("click", function () {
        var occupiedIpsStr = occupiedIps.join(",");
        window.location.href =
          "/free_ips?interface=" +
          interface +
          "&gateway_ip=" +
          gateway_ip +
          "&gateway_netmask=" +
          gateway_netmask +
          "&occupied_ips=" +
          occupiedIpsStr;
      });
      buttonContainer.appendChild(showAvailableIpsButton);
    }
  });

  socket.emit("start_ip_scan", { gateway_ip: gateway_ip });
});
