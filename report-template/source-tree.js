+(function($) {
    "use strict";

    $.sourceTree = function(elem, options) {
        this.item    = $(elem);
        this.options = $.extend({}, $.sourceTree.defaults, options);
        let self     = this;

        this.setPath(this.options.currentPath);

        this.item.find(".st-list .list-group a").on("click", function(e) {
            if($(this).attr("data-st-dir")) {
                let dir = $(this).attr("data-st-dir");

                self.appendPath(dir);
            }
            else if($(this).attr("data-st-file")) {
                let file = $(this).attr("data-st-file");
                var path = self.getPath().split('/');

                path.push(file);
                self.onPathChange(path.join('/'));
            }
            else {
                console.error("Element without data-st-dir or data-st-file");
            }

            e.preventDefault();
        });

        return this;
    };

    $.sourceTree.prototype.onPathChange = function(path) {
        if(this.options.onPathChange) {
            this.options.onPathChange(path);
        }
    };

    $.sourceTree.prototype.appendPath = function(path) {
        let oldBase = this.getPath().split('/');
        let head    = path.split('/');
        let newBase = oldBase.concat(head).join('/');

        this.setPath(newBase);
    };

    $.sourceTree.prototype.getPath = function() {
        return this.options.currentPath || "";
    };

    $.sourceTree.prototype.setPath = function(path) {
        this.options.currentPath = path;
        this.item.find(".st-path ol").empty();

        let dirs = path.split('/');
        let last = dirs.pop();
        let self = this;

        var curr = [];

        dirs.forEach(function(dir) {
            curr.push(dir);

            self.item.find(".st-path ol").append(`
                <li class="breadcrumb-item" data-st-path="${curr.join('/')}">
                    <a href="#">${dir}</a>
                </li>
            `);
        });

        curr.push(last);

        this.item.find(".st-path ol").append(`
            <li class="breadcrumb-item active" data-st-path="${curr.join('/')}" aria-current="page">
                <a href="#">${last}</a>
            </li>
        `);

        this.updatePath();
        this.updateList();

        this.onPathChange(path);
    };

    $.sourceTree.prototype.updatePath = function() {
        let self = this;

        this.item.find(".st-path ol li a").off("click").on("click", function(e) {
            let path = $(this).parent().attr("data-st-path");

            self.setPath(path);
            e.preventDefault();
        });
    };

    $.sourceTree.prototype.updateList = function() {
        let path = this.getPath();

        this.item.find(".st-list .list-group-item")
            .hide()
            .filter(`[data-st-path="${path}"]`)
            .show();
    };

    $.sourceTree.defaults = {
        currentPath:    "",
        onPathChange:   null
    };

    $.fn.sourceTree = function(options) {
        return this.each(function() {
            new $.sourceTree(this, options);
        });
    };
})(jQuery);

// Initialise

let st = $("#source-tree").sourceTree({
    currentPath: "simple_project",
    onPathChange: pathChangeHandler
});

function pathChangeHandler(path) {
    $("#cov").children()
        .hide()
        .filter(`[data-cov="${path}"]`)
        .show();
};

