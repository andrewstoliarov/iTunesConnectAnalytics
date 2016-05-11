'use strict';

var _ = require('underscore');
var moment = require('moment');

module.exports.frequency = {
  day: 'DAY',
  week: 'WEEK',
  month: 'MONTH'
};

module.exports.measures = {
  installs: 'installs',
  sessions: 'sessions',
  pageViews: 'pageViewCount',
  activeDevices: 'activeDevices',
  crashes: 'crashes',
  payingUsers: 'payingUsers',
  units: 'units',
  sales: 'sales'
};

module.exports.dimension = {
  campaigns: 'campaignId',
  websites: 'domainReferrer'
}

function Report(type, appId, config) {
  var fn = Query.prototype[type];
  if(typeof fn !== 'function'){
    throw new Error('Unknotn Report type: ' + type);
  }
	return new Query(appId, config)[type]();
}

Report.metrics = function(appId, config) {
	return new Query(appId, config).metrics();
}

Report.sources = function(appId, config) {
	return new Query(appId, config).sources();
}

var Query = function(appId, config) {
  this.config = {
    start: moment(),
    end: moment(),
    group: null,
    frequency: 'DAY',
    dimensionFilters: []
  };

  this.adamId = appId;
  this.apiURL = 'https://analytics.itunes.apple.com/analytics/api/v1';

  _.extend(this.config, config);

  return this;
};

Query.prototype.metrics = function() {
	this.endpoint 	= '/data/time-series';
	return this;
}

Query.prototype.sources = function() {
	this.endpoint 	= '/data/sources/list';
	return this;
}

Query.prototype.date = function(start, end) {
	this.config.start = toMomentObject( start );
	this.config.end = toMomentObject(
		((typeof end == 'undefined') ? start : end)
	);

	return this;
}

Query.prototype.assembleBody = function() {
  this.config.start = toMomentObject(this.config.start);
  this.config.end = toMomentObject(this.config.end);

  if (this.config.end.diff(this.config.start, 'days') === 0 && _.isArray(this._time)) {
    this.config.start = this.config.start.subtract(this._time[0], this._time[0]);
  } else if (this.config.end.diff(this.config.start) < 0) {
    this.config.start = this.config.end;
  }

  var timestampFormat = 'YYYY-MM-DD[T00:00:000Z]';

  if (!_.isArray(this.config.measures)) {
    this.config.measures = [this.config.measures];
  }

  var body = {
    startTime: this.config.start.format(timestampFormat),
    endTime: this.config.end.format(timestampFormat),
    group: this.config.group,
    frequency: this.config.frequency,
    adamId: [
      this.adamId
    ],
    dimensionFilters: this.config.dimensionFilters,
    measures: this.config.measures,
    dimension: this.config.dimension,
    limit: 200
  };

console.log(body);
  return body;
};

module.exports.Query = Query;
module.exports.Report = Report;

function toMomentObject(date) {
  if (moment.isMoment(date))
		return date;

	if (date instanceof Date)
		return moment(date);

  var regex = new RegExp(/([0-9]{4})-([0-9]{2})-([0-9]{2})/);
	if(_.isString(date) && !!(date.match(regex)))
		return moment(date, "YYYY-MM-DD");

	throw new Error('Unknown date format. Please use Date() object or String() with format YYYY-MM-DD.');
}
