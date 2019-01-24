'use strict';

var _ = require('lodash');

function ThreatReport($scope, $location, $routeParams, $timeout, dialogs, common, datacontext, threatengine, diagramming, threatmodellocator) {
    var vm = this;
    var controllerId = 'ThreatReport';
    var getLogFn = common.logger.getLogFn;
    var log = getLogFn(controllerId);
    var logError = getLogFn(controllerId, 'error');
    var scope = $scope;

    vm.title = 'Threat Model Report';
    vm.dirty = false;
    vm.graph = diagramming.newGraph();
    vm.currentDiagram = {};
    vm.diagramId = $routeParams.diagramId;
    vm.activateTab = activateTab;
    vm.editThreat = editThreat;
    vm.onAddNewThreat = onAddNewThreat;
    vm.getScopedNonFlowOrBoundaryElements = getScopedNonFlowOrBoundaryElements;

    activate();

    function activate() {
        common.activateController([], controllerId)
            .then(function () {
                log('Activated Threat Model Report View');
                initialise();
            });
    }

    function initialise() {
        var threatModelLocation = threatmodellocator.getModelLocation($routeParams);

        datacontext.load(threatModelLocation, false).then(function (threatModel) {
                onGetThreatModelDiagram(threatModel.detail.diagrams[vm.diagramId]);
            },
            onError);

        function onGetThreatModelDiagram(data) {

            if (!_.isUndefined(data.diagramJson)) {
                vm.graph.initialise(data.diagramJson);
            }
            $timeout(function() {
                document.getElementById("defaultTab").click();
            });
        }

        function onError(error) {
            // vm.errored = true;
            logError(error);
        }
    }

    function getScopedNonFlowOrBoundaryElements() {
        return vm.graph.getCells().filter(function(element) {
            return !isFlowOrBoundaryElement(element) && !element.outOfScope;
        });
    }

    function activateTab(event, tabID) {
        var i, tabcontent, tablinks;
        tabcontent = document.getElementsByClassName("tabcontent");
        for (i = 0; i < tabcontent.length; i++) {
            tabcontent[i].style.display = "none";
        }
        tablinks = document.getElementsByClassName("tablinks");
        for (i = 0; i < tablinks.length; i++) {
            tablinks[i].className = tablinks[i].className.replace(" active", "");
        }
        document.getElementById(tabID).style.display = "block";
        event.target.className += " active";
    }

    function editThreat(threat) {
        $location.search('threat', threat.id);
        dialogs.confirm('diagrams/ThreatEditPane.html', save, function () { return { heading: 'Edit Threat', threat: threat, editing: true }; }, onCancel);
    }

    function onAddNewThreat(element) {
        var newThreat = { status: 'Open', severity: 'Medium' };
        dialogs.confirm('diagrams/ThreatEditPane.html', function () {addThreat(element, newThreat);}, function () { return { heading: 'New Threat', threat: newThreat, editing: true }; }, onCancel);
    }

    function addThreat(element, threat) {
        if (!element.threats) {
            element.threats = [];
        }
        element.threats.push(threat);
        save();
    }

    function save() {
        var diagramData = { diagramJson: { cells: vm.graph.getCells() } };
        datacontext.saveThreatModelDiagram(vm.diagramId, diagramData).then(onSave());
    }

    function onSave() {
        log('Saved Changes');
    }

    function onCancel() {
        log('Cancelled');
    }

    function isFlowOrBoundaryElement(element) {
        return element.attributes.type === 'tm.Boundary' || element.attributes.type === 'tm.Flow';
    }
}
module.exports = ThreatReport;
