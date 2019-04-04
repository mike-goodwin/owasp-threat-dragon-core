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
    vm.downloadAsPDF = downloadAsPDF;
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
            return !isBoundaryElement(element) && !element.outOfScope;
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

    function isBoundaryElement(element) {
        return element.attributes.type === 'tm.Boundary';
    }

    function downloadAsPDF(){
        log("Downloading as PDF");
        var elements = getScopedNonFlowOrBoundaryElements();

        var docDefinition = {
            content: [
                {text: 'Threat Report From OWASP Threat Dragon', style: 'header', decoration: 'underline'},
                {table: {
                    headerRows: 1,
                    body: [
                        [{text:"No.", style:"tg"},{text:"COMPONENT", style:'tg'},{text:'THREAT TYPE', style:'tg'},{text:'DESCRIPTION', style:'tg'}, {text:'STATUS', style:'tg'},{text:'SEVERITY', style:'tg'} ]
                    ]
                }}
            ],
            styles: {
                header: {
                    fontSize: 30,
                    alignment: "center",
                    bold: true,
                    color: "#ff7742",
                },
                tg: {
                    fontSize: 14,
                    padding: "10",
                    overflow: 'hidden',
                    color: "#ffffff",
                    fillColor: "#094490"
                },
                easy: {
                        fillColor: '#ffffff',
                        alignment: 'left'
                },
                overEasy: {
                       fillColor: '#a0b2e9',
                        alignment: 'left'
                }
            }
        };

        var j;
        var colour;
        var i=1;
        for(var element of elements){
            j=1;
            if(element.threats != undefined) {
                docDefinition.content[1].table.body.push([{
                    rowSpan: element.threats.length+1,
                    text: i
                }, {
                    rowSpan: element.threats.length+1,
                    text: element.name
                }, {text: element.threats[0].type, style: 'noHover'}, {
                    text: element.threats[0].description
                }, {text: element.threats[0].status, style: 'noHover'}, {
                    text: element.threats[0].severity
                }]);
                j++;
                for (var threat of element.threats) {
                    if(j%2==0){ colour="overEasy";} else{colour="easy";}
                    docDefinition.content[1].table.body.push(["", "", {text: threat.type, style: colour}, {text: threat.description, style: colour}, {text: threat.status, style:colour}, {text: threat.severity, style:colour}]);
                    j++;
                }
                i++;
            }
        }

        pdfMake.createPdf(docDefinition).download("ThreatReport.pdf");

    }

}
module.exports = ThreatReport;
