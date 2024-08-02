document
  .getElementById("configure_ip_form")
  .addEventListener("submit", function (event) {
    event.preventDefault();
    var form = event.target;
    var formData = new FormData(form);

    fetch(form.action, {
      method: form.method,
      body: formData,
    })
      .then((response) => response.text())
      .then((data) => {
        var interface = formData.get("interface");
        var selected_ip = formData.get("selected_ip");
        var gateway_netmask = formData.get("gateway_netmask");
        var gateway_ip = formData.get("gateway_ip");
        window.location.href =
          "{{ url_for('main.config_termination') }}?interface=" +
          interface +
          "&selected_ip=" +
          selected_ip +
          "&gateway_netmask=" +
          gateway_netmask +
          "&gateway_ip=" +
          gateway_ip;
      });
  });
