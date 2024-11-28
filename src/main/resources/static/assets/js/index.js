//------------------------------------Ticket Home----------------------------------------------
        $(document).ready(function () {

            ////To Make My Table is a DataTable
            //$("#currentTickets").DataTable();
            //$("#exTickets").DataTable();

            $("#currentTickets").on("click", ".js-delete", function () {
                var button = $(this);
                bootbox.confirm("Are You Sure You Want to Delete This Ticket!", function (result) {
                    if (result) {
                        $.ajax({
                            url: "/Passengers/CancelBooking/" + button.attr("data-passenger-id") + "/" + button.attr("data-ticket-id"),
                            method: "Delete",
                            success: function () {
                                button.parents("tr").remove();
                                toastr.success("Successful Process");
                            },
                            fail: function () {
                                toastr.error("Can't Operate This Process");
                            }
                        });
                    }
                });
            });
        });
   

//----------------Seats----------------------------------------------------------
$(document).ready(function () {
    //To Make My Table is a DataTable
    $("#users").DataTable();
});
//-----------------Passenger--------------------------------------------------
$(document).ready(function () {
    //To Make My Table is a DataTable
    $("#passengers").DataTable();
});
//-------------------------Trip-------------------------------------------------
$(document).ready(function () {
    //To Make My Table is a DataTable
    $("#trips").DataTable();

    $("#trips").on("click", ".js-delete", function () {
        var button = $(this);
        bootbox.confirm("Are You Sure You Want to Delete This Trip!", function (result) {
            if (result) {
                $.ajax({
                    url: "/Admin/DeleteTrip/" + button.attr("data-trip-id"),
                    method: "Delete",
                    success: function () {
                        button.parents("tr").remove();
                        toastr.success("Successful Process");
                    },
                    fail: function () {
                        toastr.error("Can't Operate This Process");
                    }
                });
            }
        });
    });
});
//----------Bus---------------------------------
$(document).ready(function () {
    //To Make My Table is a DataTable
    $("#buses").DataTable();

    $("#buses").on("click", ".js-delete", function () {
        var button = $(this);
        bootbox.confirm("Are You Sure You Want to Delete This Bus!", function (result) {
            if (result) {
                $.ajax({
                    url: "/Admin/DeleteBus/" + button.attr("data-bus-id"),
                    method: "Delete",
                    success: function () {
                        button.parents("tr").remove();
                        toastr.success("Successful Process");
                    },
                    fail: function () {
                        toastr.error("Can't Operate This Process");
                    }
                });
            }
        });
    });
});
//-----------------------------------------Driver----------------------------------------------------
$(document).ready(function () {
    //To Make My Table is a DataTable
    $("#drivers").DataTable();

    $("#drivers").on("click", ".js-delete", function () {
        var button = $(this);
        bootbox.confirm("Are You Sure You Want to Delete This Bus!", function (result) {
            if (result) {
                $.ajax({
                    url: "/Admin/DeleteDriver/" + button.attr("data-bus-id"),
                    method: "Delete",
                    success: function () {
                        button.parents("tr").remove();
                        toastr.success("Successful Process");
                    },
                    fail: function () {
                        toastr.error("Can't Operate This Process");
                    }
                });
            }
        });
    });
});
/////////////////////////-----------------------Line----------------------------

       
$(document).ready(function () {
    //To Make My Table is a DataTable
    $("#lines").DataTable();

    $("#lines").on("click", ".js-delete", function () {
        var button = $(this);
        bootbox.confirm("Are You Sure You Want to Delete This Line!", function (result) {
            if (result) {
                $.ajax({
                    url: "/Admin/DeleteLine/" + button.attr("data-line-id"),
                    method: "Delete",
                    success: function () {
                        button.parents("tr").remove();
                        toastr.success("Successful Process");
                    },
                    fail: function () {
                        toastr.error("Can't Operate This Process");
                    }
                });
            }
        });
    });
});

//---------------------------------Tickets------------------------------------------------------

$(document).ready(function () {
    //To Make My Table is a DataTable
    $("#tickets").DataTable();

    $("#tickets").on("click", ".js-delete", function () {
        var button = $(this);
        bootbox.confirm("Are You Sure You Want to Delete This Ticket!", function (result) {
            if (result) {
                $.ajax({
                    url: "/Admin/DeleteTicket/" + button.attr("data-passenger-id") + "/" + button.attr("data-ticket-id"),
                    method: "Delete",
                    success: function () {
                        button.parents("tr").remove();
                        toastr.success("Successful Process");
                    },
                    fail: function () {
                        toastr.error("Can't Operate This Process");
                    }
                });
            }
        });
    });

    //Blocking 
    $("#tickets").on("click", ".js-Block", function () {
        var button = $(this);
        bootbox.confirm("Are You Sure You Want to Block This Ticket!", function (result) {
            if (result) {
                $.ajax({
                    url: "/Admin/BlockTicket/" + button.attr("data-passenger-id") + "/" + button.attr("data-ticket-id"),
                    method: "Delete",
                    success: function () {
                        if (button.text().toLowerCase() == "block") {
                            button.text("Unblock");
                            button.removeClass("btn-warning");
                            button.addClass("btn-success");
                            toastr.success("Successful Process");
                        }
                        else if (button.text().toLowerCase() == "unblock") {
                            button.text("Block");
                            button.removeClass("btn-success");
                            button.addClass("btn-warning");
                            toastr.success("Successful Process");
                        }

                    },
                    fail: function () {
                        toastr.error("Can't Operate This Process");
                    }
                });
            }
        });
    });
});

$(document).ready(function () {
    //To Make My Table is a DataTable
    $("#feedbacks").DataTable();
});

$(document).ready(function () {
    //To Make My Table is a DataTable
    $("#messages").DataTable();
});


