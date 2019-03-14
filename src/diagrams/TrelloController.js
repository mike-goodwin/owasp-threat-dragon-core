'use strict';

var _ = require('lodash');
function TrelloController($scope, $window, common) {

    var TRELLO = require("trello");
    var key = 'b82c0df7859c4b1d0d96a1840f1333fd';
    var token = '1540b46b2a759ab55ec0f4485b2861bc9be1e71a3101945e7aae73b335a7f06a';
    var trello = new TRELLO(key, token);
    var getLogFn = common.logger.getLogFn;
    var log = getLogFn('TrelloController');
    $scope.isTrelloActive = false;
    $scope.boards = [];
    $scope.toggle = function () {
        $scope.isTrelloActive = !$scope.isTrelloActive;
    };
    $scope.getBoards = function() {
        trello.getBoards('me', function (error, boards) {
            if (error) {
                log("Could Not Get Boards: ", error);
            } else {
                log("found " + boards.length + " boards");
                $scope.boards = boards;
                $scope.getLists();
            }
        });
    }
    $scope.getLists=function getLists(){
        for (var i=0; i<$scope.boards.length; i++){
            $scope.getListsWithBoardId($scope.boards[i].id, i);
        }
    };

    $scope.getListsWithBoardId = function getListsWithBoardId(boardId, index){
        trello.getListsOnBoard(boardId, function(error, lists){
            if (error) {
                log("Could Not Get Boards: ", error);
            } else {
                log("found " + lists.length + " lists on board:"+boardId);
                console.log(lists);
                $scope.boards[index].lists = lists;
            }
        });
    };

    $scope.$watch('threatEditForm.boardInput', function(newVal, oldVal){
        if(newVal!=oldVal) {
            log(newVal);
            if (newVal.id) {
                $scope.getListsFromDictionary(newVal.id);
                $scope.shortUrl = newVal.shortUrl;
                //$scope.getListsFromBoard(newVal);
            }
        }
    }, true);

    $scope.getListsFromDictionary = function getListsFromDictionary(boardId){
        for (var i=0; i<$scope.boards.length; i++) {
            if($scope.boards[i].id == boardId){
                $scope.ourLists = $scope.boards[i].lists;
            }
        }
    };

    $scope.addCard = function (cardName, cardDescription, listId){

        trello.addCard(cardName, cardDescription, listId, function (error, cardAdded) {
            if (error) {
                log("Could Not Add Card: ", error);
            } else {
                log("Card added: ", cardAdded.name);
                $scope.toggle();
            }
        });
    };

    $scope.goToBoard = function () {
        $window.open($scope.shortUrl);
    };

}module.exports = TrelloController;
