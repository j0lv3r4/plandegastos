(function($) {
  var picker = new Pikaday({
    field: document.getElementById('datepicker'),
    format: 'D MMM YYYY',
    onSelect: function() {
      console.log(this.getMoment().format('Do MMMM YYYY'));
    }
  });
})(jQuery);
