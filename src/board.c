/*-
 * Copyright (c) 2024 Ruslan Bukin <br@bsdpad.com>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/cdefs.h>
#include <sys/console.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/spinlock.h>
#include <sys/malloc.h>
#include <sys/mutex.h>
#include <sys/sem.h>
#include <sys/list.h>
#include <sys/smp.h>
#include <sys/of.h>
#include <dev/gpio/gpio.h>

#include <machine/vmparam.h>
#include <machine/cpuregs.h>
#include <machine/cpufunc.h>

#include <arch/riscv/artinchip/d21x.h>

#include <dev/uart/uart_16550.h>

#include "board.h"

static struct uart_16550_softc uart_sc;
static struct mdx_device uart_dev = { .sc = &uart_sc };

#if 1
static struct d21x_gpio_softc gpio_sc;
static struct mdx_device gpio_dev = { .sc = &gpio_sc };
#endif

static struct d21x_cmu_softc cmu_sc;
static struct mdx_device cmu_dev = { .sc = &cmu_sc };

#define PIN_CFG(g, p)   (0x80 + (g) * 0x100 + (p) * 0x4)
#define OUT_CFG(g)      (0x04 + (g) * 0x100)
#define OUT_SET(g)      (0x14 + (g) * 0x100)

void (*test)(void);

void
board_init(void)
{

	d21x_cmu_init(&cmu_dev, BASE_CMU);
	d21x_cmu_clk_enable(&cmu_dev, D21X_CLK_GPIO, 0);
	d21x_cmu_clk_enable(&cmu_dev, D21X_CLK_GTC, 20);
	d21x_cmu_clk_enable(&cmu_dev, D21X_CLK_UART2, 25);

#if 0
	uint64_t addr;
	uint32_t reg;

        addr = BASE_GPIO + PIN_CFG(3, 8);
        reg = 5 | (3 << 4);
        *(uint32_t *)addr = reg;

        addr = BASE_GPIO + PIN_CFG(3, 9);
        reg = 5 | (3 << 4);
        *(uint32_t *)addr = reg;

        addr = BASE_GPIO + PIN_CFG(3, 10);
        reg = *(uint32_t *)addr;
        reg = 1 | (3 << 4) | 1 << 17;
        *(uint32_t *)addr = reg;

        /* D.10 is out */
        addr = BASE_GPIO + OUT_CFG(3);
        *(uint32_t *)addr = (1 << 10);

        /* D.10 out set */
        addr = BASE_GPIO + OUT_SET(3);
        *(uint32_t *)addr = (1 << 10);
#else
	d21x_gpio_init(&gpio_dev, BASE_GPIO);
	mdx_gpio_set_function(&gpio_dev, GRP_PD, 8, PIN_PD8_UART2_TX);
	mdx_gpio_set_function(&gpio_dev, GRP_PD, 9, PIN_PD9_UART2_RX);
	mdx_gpio_set_function(&gpio_dev, GRP_PD, 10, PIN_FUNC_GPIO);
	mdx_gpio_set_function(&gpio_dev, GRP_PD, 11, PIN_FUNC_GPIO);
	mdx_gpio_configure(&gpio_dev, GRP_PD, 10, MDX_GPIO_OUTPUT);
	mdx_gpio_configure(&gpio_dev, GRP_PD, 11, MDX_GPIO_OUTPUT);
	mdx_gpio_set(&gpio_dev, GRP_PD, 10, 1);
	mdx_gpio_set(&gpio_dev, GRP_PD, 11, 1);
#endif

	uart_16550_init(&uart_dev, (void *)BASE_UART2, 2, 48000000);
	uart_16550_setup(&uart_dev, 115200, UART_DATABITS_8, UART_STOPBITS_1,
	    UART_PARITY_NONE);

	mdx_console_register_uart(&uart_dev);

	while (1) {
		printf("test %p\n", uart_dev.ops);
		//*(uint32_t *)BASE_UART2 = 0x61;
		//mdx_uart_putc(&uart_dev, 0x61);
	}
}
