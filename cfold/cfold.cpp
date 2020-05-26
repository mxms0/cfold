// cfold - Some better code folding in IDA
// i.e. it won't collapse the `else` everytime you collapse the if
// Released under BSD 3-Clause where applicable

#include <hexrays.hpp>

// Hex-Rays API pointer
hexdsp_t *hexdsp = NULL;

static bool inited = false;

// The node to keep inverted-if information.
static const char nodename[] = "$ cfolded";
static netnode node;

// Cached copy of inverted if-statement addresses
static eavec_t folded_scopes;

#define FOLD_ACTION_NAME "foldcode"
#define UNFOLD_ACTION_NAME "unfoldcode"

static void do_collapse_scope(cinsn_t *i) {
    i->cblock->clear();
    
    cinsn_t host;
    host.ea = i->ea;

    cexpr_t *breadcrumbs = new cexpr_t(cot_helper, NULL);
    // This is being leaked, probably. Where do i free this?
    char *bf = (char *)malloc(10);
    // Sorry, strcpy, strncpy is banned
    bf[0] = '{';
    bf[1] = ' ';
    bf[2] = '.';
    bf[3] = '.';
    bf[4] = '.';
    bf[5] = ' ';
    bf[6] = '}';
    bf[7] = 0;

    breadcrumbs->helper = bf;
    breadcrumbs->exflags = EXFL_ALONE;

    host.cexpr = breadcrumbs;
    host.op = cit_expr;

    i->cblock->push_front(host);
}

static void add_collapsed_scope(ea_t ea) {
    folded_scopes.push_back(ea); 
    // save to db
	eavec_t copy = folded_scopes;
	for (int i = 0; i < copy.size(); i++)
		copy[i] = ea2node(copy[i]);
	node.setblob(copy.begin(), copy.size() * sizeof(ea_t), 0, 'I');
}

static void remove_collapsed_scope(ea_t ea) {
    eavec_t::iterator p = folded_scopes.find(ea);
    if (p != folded_scopes.end())
        folded_scopes.erase(p);
    // save to db
	eavec_t copy = folded_scopes;
	for (int i = 0; i < copy.size(); i++)
		copy[i] = ea2node(copy[i]);
	node.setblob(copy.begin(), copy.size() * sizeof(ea_t), 0, 'I');
}

static bool is_collapsed_nearby(vdui_t &vu) {
    struct ida_local ea_finder_t : public ctree_visitor_t {
        ea_t ea;
        cinsn_t *found;
        ea_finder_t(ea_t e) : ctree_visitor_t(CV_PARENTS), ea(e) {}
        int idaapi visit_insn(cinsn_t *i) {
            if (i->ea == ea && i->op == cit_block) {
                found = i;
                return 1;
            }
            return 0;
        }
    };
    ea_finder_t iff(vu.tail.loc.ea);
    if (!iff.apply_to(&vu.cfunc->body, NULL))
        return false;

    if (iff.found) {
        eavec_t::iterator p = folded_scopes.find(iff.found->ea);
        if (p != folded_scopes.end())
            return true;
    }

    return false;
}

static cinsn_t *find_collapsable_scope(vdui_t &vu) {
    ea_t ea = vu.item.get_ea();
    struct ida_local ea_finder_t : public ctree_visitor_t {
        ea_t ea;
        cinsn_t *found;
        ea_finder_t(ea_t e) : ctree_visitor_t(CV_PARENTS), ea(e) {}
        int idaapi visit_insn(cinsn_t *i) {
            if (i->ea == ea && i->op == cit_block) {
                found = i;
                return 1;
            }
            return 0;
        }
    };

    ea_finder_t iff(vu.tail.loc.ea);
    if (iff.apply_to(&vu.cfunc->body, NULL))
        return iff.found;

	return NULL;
}

static void collapse_scopes(cfunc_t *cfunc) {
    // I think it's not exactly safe to modify the tree while visiting it ;P
    // Actually seems fine..
	struct ida_local block_collapser : public ctree_visitor_t {
		block_collapser() : ctree_visitor_t(CV_INSNS | CV_PARENTS) {}
		int idaapi visit_insn(cinsn_t *i) {
            if (i->op == cit_block && folded_scopes.has(i->ea)) {
                do_collapse_scope(i);
            }
			return 0;
		}
	};

	block_collapser bc;
    bc.apply_to(&cfunc->body, NULL); 
}

static int idaapi callback(void *, hexrays_event_t event, va_list va) {
	switch (event) {
		case hxe_populating_popup: { 
				TWidget *widget = va_arg(va, TWidget *);
				TPopupMenu *popup = va_arg(va, TPopupMenu *);
				vdui_t &vu = *va_arg(va, vdui_t *);
                if (is_collapsed_nearby(vu)) {
					attach_action_to_popup(widget, popup, UNFOLD_ACTION_NAME);
                }
                else if (find_collapsable_scope(vu) != NULL)
					attach_action_to_popup(widget, popup, FOLD_ACTION_NAME);
			}
			break;
		case hxe_maturity:
			if (!folded_scopes.empty()) { 
				cfunc_t *cfunc = va_arg(va, cfunc_t *);
				ctree_maturity_t new_maturity = va_argi(va, ctree_maturity_t);
				if (new_maturity == CMAT_NICE) {
                    // Unfortunately, IDA doesn't like unused labels,
                    // and asserts on them. see verifier.cpp:605
                    // So if we collapse here, the label goes away
                    // and uncollapsing makes it magically appear again
                    // It's not great, but it'll do in the meantime 
                    collapse_scopes(cfunc);
                }
                cfunc->verify(ALLOW_UNUSED_LABELS, true);
			}
			break;
		default:
			break;
	}
	return 0;
}

struct code_folder_action_t : public action_handler_t {
	virtual int idaapi activate(action_activation_ctx_t *ctx) {
		vdui_t &vu = *get_widget_vdui(ctx->widget);
		cinsn_t *i = find_collapsable_scope(vu);
		add_collapsed_scope(i->ea);
        do_collapse_scope(i);
		vu.refresh_ctext();
		return 1;
	}

	virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
		vdui_t *vu = get_widget_vdui(ctx->widget);
		if (vu == NULL)
			return AST_DISABLE_FOR_WIDGET;
        return AST_ENABLE;
        // We really should see if it's possible to enable here, but it .. seems to do the right thing
        // However, the fold option isnt available in switch/case for some reason..
		//return find_collapsable_scope(*vu) == NULL ? AST_DISABLE : AST_ENABLE;
	}
};

struct code_unfolder_action_t : public action_handler_t {
	virtual int idaapi activate(action_activation_ctx_t *ctx) {
		vdui_t &vu = *get_widget_vdui(ctx->widget);
		cinsn_t *i = find_collapsable_scope(vu);
        
        remove_collapsed_scope(i->ea);

        // This is expensive, however
        // if we don't, we end up with some funky
        // decompilation, and missing vars
        vu.refresh_view(true);
		vu.refresh_ctext();
		return 1;
	}

	virtual action_state_t idaapi update(action_update_ctx_t *ctx) {
		vdui_t *vu = get_widget_vdui(ctx->widget);
		if (vu == NULL)
			return AST_DISABLE_FOR_WIDGET;
        return AST_ENABLE;
	}
};

static code_folder_action_t code_folder_action;
static const action_desc_t fold_action =
    ACTION_DESC_LITERAL(FOLD_ACTION_NAME, "Fold Code", &code_folder_action, NULL, NULL, -1);

static code_unfolder_action_t code_unfolder_action;
static const action_desc_t unfold_action =
    ACTION_DESC_LITERAL(UNFOLD_ACTION_NAME, "Unfold Code", &code_unfolder_action, NULL, NULL, -1);

int idaapi init(void) {
	if (!init_hexrays_plugin()) return PLUGIN_SKIP; 

    // Load folds from db
	if (!node.create(nodename))  {
		size_t n;
		void *blob = node.getblob(NULL, &n, 0, 'I');
		if ( blob != NULL ) {
			folded_scopes.clear();
			folded_scopes.inject((ea_t *)blob, n / sizeof(ea_t));
			for (int i = 0; i < folded_scopes.size(); i++)
				folded_scopes[i] = node2ea(folded_scopes[i]);
		}
	}

	install_hexrays_callback(callback, NULL);
    
	register_action(fold_action);
	register_action(unfold_action);
	inited = true;

	return PLUGIN_KEEP;
}

void idaapi term(void) {
	if (inited) {
		remove_hexrays_callback(callback, NULL);
		term_hexrays_plugin();
	}
}

bool idaapi run(size_t) { return false; }

static char comment[] = "Code Folding";

plugin_t PLUGIN = {
	IDP_INTERFACE_VERSION,
	PLUGIN_HIDE,          // plugin flags
	init,                 // initialize
	term,                 // terminate. this pointer may be NULL.
	run,                  // invoke plugin
	comment,              // long comment about the plugin
	"",                   // multiline help about the plugin
	"Code Folding", // the preferred short name of the plugin
	""                    // the preferred hotkey to run the plugin
};

