$(document).ready(function () {
  $.get("{{ url_for('main.check_configuration_status') }}", function (data) {
    if (data.status === "done") {
      $("h1")
        .text(
          "Configuration terminated! Check using the command ip a in your terminal"
        )
        .css("text-align", "center");
    }
  });
});
