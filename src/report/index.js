'use strict';

var core = angular.module('owasp-threat-dragon-core');
core.controller('ThreatReport', ['$scope', '$location', '$routeParams', '$timeout', 'dialogs', 'common', 'datacontext', 'threatengine', 'diagramming', 'threatmodellocator', require('./ThreatReport')]);
