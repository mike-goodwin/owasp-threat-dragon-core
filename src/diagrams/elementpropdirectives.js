'use strict';

var $ = require('jquery');
var supportedLanguages = require("../../tools/Supported_Languages");
var Prism = require('prismjs');
require('prismjs/plugins/normalize-whitespace/prism-normalize-whitespace.js');
require('prismjs/plugins/line-numbers/prism-line-numbers.js');
require('prismjs/plugins/autoloader/prism-autoloader');
Prism.plugins.autoloader.use_minified = false;
Prism.plugins.autoloader.languages_path = '/prismjs/components/';

function modalClose() {

    var directive =
        {
            link: link,
            templateUrl: function (elem, attrs) { return attrs.templateUrl; },
            restrict: 'E',
            scope:
            {
                action: '&',
                newClass: '@',
            }
        };

    return directive;

    function link(scope, element, attrs) {

        scope.onAction = function () {

            var el = $("[role='dialog']");
            var windowClass = el.attr("window-class");
            el.removeClass(windowClass);
            el.addClass(scope.newClass);
            scope.action();
        };
    }

}

function prismHighlight() {
    return {
        link: link,
        restrict: 'A'
    };

    function link(scope, element, attrs) {
        element.ready(function() {
            Prism.highlightElement(element[0]);
        });
    }
}

function exampleEditor(dialogs) {

    var directive =
        {
            link: link,
            restrict: 'E',
            require: '^form',
            scope:
            {
                examples: '=',
                onNewThreatExample: '&'
            },
            template: "<button ng-click='onNewThreatExample()' class='btn btn-link' style='border-radius: 10px; padding: 5px; border: 1px solid orangered;' role='button' data-toggle='tooltip' data-placement='top' title='Add a new example'><span class='glyphicon glyphicon-plus'></span> New snippet </button>",
        };
    var newExample = {};

    return directive;

    function link(scope, element, attrs, threatEditForm) {
        scope.onNewThreatExample = function () {
            dialogs.confirm('diagrams/NewExamplePane.html', scope.addThreatExample, function () { return { heading: 'New Snippet', supportedLanguages: supportedLanguages, example: newExample, editing: true }; }, reset);
        };

        scope.addThreatExample = function () {
            if (!scope.examples) {
                scope.examples = [];
            }
            newExample.language = getLanguageByAlias(newExample.language.highlightAlias);
            scope.examples.push(newExample);
            threatEditForm.$setDirty();
            reset();
        };

        function getLanguageByAlias(alias) {
            for(var index = 0; index < supportedLanguages.length; index++) {
                var supportedLanguage = supportedLanguages[index];
                if (supportedLanguage.highlightAlias === alias) {
                    return supportedLanguage;
                }
            }
            return null;
        }
    }

    function reset() {
        newExample = {};
    }
}

function referenceEditor(dialogs) {

    var directive =
        {
            link: link,
            restrict: 'E',
            require: '^form',
            scope:
                {
                    references: '=',
                    onReference: '&'
                },
            template: "<button ng-click='onNewReference()' class='btn btn-link' style='border-radius: 10px; padding: 5px; border: 1px solid orangered;' role='button' data-toggle='tooltip' data-placement='top' title='Add a new reference'><span class='glyphicon glyphicon-plus'></span> New reference </button>",
        };
    var newReference = {};

    return directive;

    function link(scope, element, attrs, threatEditForm) {
        scope.onNewReference = function () {
            dialogs.confirm('diagrams/NewReferencePane.html', scope.addReference, function () { return { heading: 'New Reference', reference: newReference, regex: "^(http[s]?:\\/\\/){0,1}(www\\.){0,1}[a-zA-Z0-9\\.\\-]+\\.[a-zA-Z]{2,5}[\\.]{0,1}", editing: true }; }, reset);
        };

        scope.addReference = function () {
            if (!scope.references) {
                scope.references = [];
            }
            newReference.link = getHttpsUrl(newReference.link);
            scope.references.push(newReference);
            threatEditForm.$setDirty();
            reset();
        };
        function getHttpsUrl(url) {
            if (!/^(f|ht)tps?:\/\//i.test(url)) {
                url = "https://" + url;
            }
            return url;
        }
    }

    function reset() {
        newReference = {};
    }
}

function elementProperties(common) {

    var directive =
        {
            link: link,
            templateUrl: 'diagrams/ElementPropertiesPane.html',
            restrict: 'E',
            scope:
            {
                selected: '=',
                elementType: '@',
                edit: '&'
            }
        };

    return directive;

    function link(scope, element, attrs) {
    }

}

function elementThreats($routeParams, $location, common, dialogs) {

    var directive =
        {
            link: link,
            templateUrl: 'diagrams/ThreatSummaryPane.html',
            restrict: 'E',
            scope:
            {
                threats: '=',
                save: '&'
            }
        };

    var newThreat = initialiseThreat();
    var editIndex = null;
    var originalThreat = {};
    var getLogFn = common.logger.getLogFn;
    var logError = getLogFn('tmtElementThreats', 'error');

    return directive;

    function link(scope, element, attrs) {
        scope.applyToAll = false;

        scope.onNewThreat = function () {
            dialogs.confirm('diagrams/ThreatEditPane.html', scope.addThreat, function () { return { heading: 'New Threat', threat: newThreat, editing: true }; }, reset);
        };

        scope.onEditThreat = function (index) {
            editIndex = index;
            originalThreat = angular.copy(scope.threats[index]);
            $location.search('threat', originalThreat.id);
            dialogs.confirm('diagrams/ThreatEditPane.html', scope.editThreat, function () { return { heading: 'Edit Threat', threat: scope.threats[index], editing: true }; }, scope.cancelEdit);
        };

        scope.removeThreat = function (index) {
            scope.threats.splice(index, 1);
            scope.save();
        };

        scope.addThreat = function () {

            if (!scope.threats) {
                scope.threats = [];
            }

            scope.threats.push(newThreat);
            scope.save({ threat: newThreat });
            reset();
        };

        scope.editThreat = function () {
            scope.save();
            reset();
        };

        scope.cancelEdit = function () {
            scope.threats[editIndex] = originalThreat;
            reset();
        };

        var threatId = $routeParams.threat;

        if (angular.isDefined(threatId)) {
            var matchingIndex = -1;

            scope.threats.forEach(function (threat, index) {
                if (threat.id == threatId) {
                    matchingIndex = index;
                }
            });

            if (matchingIndex >= 0) {
                scope.onEditThreat(matchingIndex);
            }
            else {
                logError('Invalid threat ID');
                $location.search('threat', null);
            }
        }
    }

    function reset() {
        newThreat = initialiseThreat();
        editIndex = null;
        $location.search('threat', null);
    }

    function initialiseThreat() {
        return { status: 'Open', severity: 'Medium' };
    }

}

module.exports = {
    modalClose: modalClose,
    prismHighlight: prismHighlight,
    elementProperties: elementProperties,
    exampleEditor: exampleEditor,
    referenceEditor: referenceEditor,
    elementThreats: elementThreats
};
