'use strict';

var joint = require('jointjs');

function diagramming() {

    var zoomScaleFactor = 1.25;

    //graph extensions

    joint.dia.Graph.prototype.initialise = function (diagramJson) {

        this.fromJSON(diagramJson);

    };

    joint.dia.Graph.prototype.addProcess = function () {
        var cell = newElement(joint.shapes.tm.Process, 50, 50, 'process ' + this.attributes.cells.length);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addSmartWatch = function () {
        var cell = newElementWithLabelBelow(joint.shapes.tm.SmartWatch, 50, 50, 'Smart Watch ' + this.attributes.cells.length, 90);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addLaptop = function () {
        var cell = newElementWithLabelBelow(joint.shapes.tm.Laptop, 50, 50, 'Laptop ' + this.attributes.cells.length, 90);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addPacemaker = function () {
        var cell = newElementWithLabelBelow(joint.shapes.tm.Pacemaker, 50, 50, 'Pacemaker ' + this.attributes.cells.length, 90);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addMobilePhone = function () {
        var cell = newElementWithLabelBelow(joint.shapes.tm.MobilePhone, 50, 50, 'Mobile Phone ' + this.attributes.cells.length, 90);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addTablet = function () {
        var cell = newElementWithLabelBelow(joint.shapes.tm.Tablet, 50, 50, 'Tablet ' + this.attributes.cells.length, 90);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addElectrocardiogram = function () {
        var cell = newElementWithLabelBelow(joint.shapes.tm.Electrocardiogram, 50, 50, 'Electrocardiogram ' + this.attributes.cells.length, 90);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addStore = function () {
        var cell = newElement(joint.shapes.tm.Store, 50, 50, 'store ' + this.attributes.cells.length);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addActor = function () {
        var cell = newElement(joint.shapes.tm.Actor, 50, 50, 'actor ' + this.attributes.cells.length);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addFlow = function (source, target) {
        var cell = flow(source, target, 'flow ' + this.attributes.cells.length);
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.addBoundary = function () {
        var cell = boundary();
        this.addCell(cell);

        return cell;
    };

    joint.dia.Graph.prototype.clearAll = function () {
        this.clear(true);
    };

    joint.dia.Graph.prototype.cellCount = function () {
        return this.attributes.cells.length;
    };

    joint.dia.Graph.prototype.getCellById = function (id) {
        return this.getCell(id);
    };

    //diagram extensions

    joint.dia.Paper.prototype.resize = function (size) {
        this.setDimensions(size.width, size.height);
    };

    joint.dia.Paper.prototype.scaleContent = function () {
        this.scaleContentToFit();
    };

    joint.dia.Paper.prototype.zoom = function (zoomLevel) {
        var factor = Math.pow(zoomScaleFactor, zoomLevel);
        this.scale(factor, factor);
    };

    // Define the functions and properties to reveal.
    var service = {
        newGraph: newGraph,
        newDiagram: newDiagram,
        Process: joint.shapes.tm.Process,
        SmartWatch: joint.shapes.tm.SmartWatch,
        Laptop: joint.shapes.tm.Laptop,
        Pacemaker: joint.shapes.tm.Pacemaker,
        MobilePhone: joint.shapes.tm.MobilePhone,
        Tablet: joint.shapes.tm.Tablet,
        Electrocardiogram: joint.shapes.tm.Electrocardiogram,
        Store: joint.shapes.tm.Store,
        Actor: joint.shapes.tm.Actor,
        Flow: joint.shapes.tm.Flow,
        Boundary: joint.shapes.tm.Boundary
    };

    return service;

    function newGraph() {
        return new joint.dia.Graph();
    }

    function newDiagram(height, width, gridSize, graph, target, interactive) {

        var paper = new joint.dia.Paper({
            width: width,
            height: height,
            gridSize: gridSize,
            model: graph,
            interactive: interactive
        });

        target.appendChild(paper.el);

        return paper;
    }

    //private

    function newElement(ShapeClass, x, y, label) {
        return new ShapeClass({
            position: { x: x, y: y },
            attrs: { text: { text: label } }
        });
    }

    function newElementWithLabelBelow(ShapeClass, x, y, label, labelPosition) {
        return new ShapeClass({
            position: { x: x, y: y },
            attrs: {
                text: { text: label, 'ref-y': labelPosition}
            }
        });
    }

    function flow(source, target, label) {

        var newTarget = target ? { id: target.id } : { x: 110, y: 100 };
        var newSource = source ? { id: source.id } : { x: 30, y: 20 };

        var cell = new joint.shapes.tm.Flow({
            target: newTarget,
            source: newSource,
            vertices: []
        });

        cell.setLabel(label);

        return cell;
    }

    function boundary(source, target, label) {

        var cell = new joint.shapes.tm.Boundary({
            target: target ? target : { x: 110, y: 100 },
            source: source ? source : { x: 30, y: 20 },
            vertices: []
        });

        if (label) {
            cell.setLabel(label);
        }

        return cell;
    }
}

module.exports = diagramming;
