'use strict';

var core = angular.module('owasp-threat-dragon-core');
var diagramdirectives = require('./diagramdirectives');
var elementPropertyDirectives = require('./elementpropdirectives');
var diagram = require('./diagram');
var TrelloController = require('./TrelloController');
core.directive('tmtStencil', ['diagramming', diagramdirectives.stencil]);
core.directive('tmtDiagram', ['common', 'diagramming', diagramdirectives.diagram]);
core.directive('tmtModalClose', [elementPropertyDirectives.modalClose]);
core.directive('tmtElementProperties', [elementPropertyDirectives.elementProperties]);
core.directive('tmtElementThreats', ['$routeParams', '$location', 'common', 'dialogs', elementPropertyDirectives.elementThreats]);
core.controller('diagram', ['$scope', '$location', '$routeParams', '$timeout', 'dialogs', 'common', 'datacontext', 'threatengine', 'diagramming', 'threatmodellocator', diagram]);
core.controller('TrelloController', ['$scope', '$window', 'common', TrelloController]);
