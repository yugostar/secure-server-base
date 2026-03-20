package com.security.serverbase.license.dto;

public record TicketResponse(
        Ticket ticket,
        String signature
) {
}
