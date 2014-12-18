(function($) {
  var $calendar = $('#calendar');
  
  var events = {
    events: [
      { title: 'Event1', start:'2014-12-14' },
      { title: 'Event1', start:'2014-12-14' },
      { title: 'Event1', start:'2014-12-14' },
      { title: 'Event1', start:'2014-12-14' },
      { title: 'Event1', start:'2014-12-14' },
      { title: 'Event1', start:'2014-12-14' },
      {
        title: 'Event2',
        start: '2014-12-18'
      }
    ],
    color: 'yellow',
    textColor: 'black'
  };

  $calendar.fullCalendar({
    events: events,
    eventLimit: 2,
    eventLimitText: "More"
  });
})(jQuery);
